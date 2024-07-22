use super::{get_step_conf, get_str_conf, get_str_slice_conf, Error, Plugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::USER_AGENT;
use http::StatusCode;
use pingora::proxy::Session;
use regex::Replacer;
use tracing::{debug, info};
use wirefilter::{ExecutionContext, Type, Scheme};

pub struct WirefilterPlugin {
    plugin_step: PluginStep,
    restriction_expression_list: Vec<String>,
    forbidden_resp: HttpResponse,
}

impl TryFrom<&PluginConf> for WirefilterPlugin {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);
        let exps = get_str_slice_conf(value, "restriction_expression_list");
        
        //Check expression
        let scheme = get_scheme();  
        for exp in exps.iter() {
            let input = exp.as_str();
            let is_exp_err = scheme.parse(input).is_err();
            if is_exp_err {
                let exp_err = scheme.parse(input).unwrap_err().to_string();
                println!("Parsing restriction expression error : {exp_err:?}");
                info!(exp_err, "Parsing restriction expression error: ");
                return Err(Error::Invalid {
                    category: PluginCategory::WirefilterPlugin.to_string(),
                    message: exp_err,
                });
            }
        }
        
        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Ha ha ha... Request is forbidden".to_string();
        }

        let params = Self {
            plugin_step: step,
            restriction_expression_list: exps,
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream]
            .contains(&params.plugin_step)
        {
            return Err(Error::Invalid {
                category: PluginCategory::WirefilterPlugin.to_string(),
                message: "Referer Wirefilter restriction plugin should be executed at request or proxy upstream step".to_string(),
            });
        }
        Ok(params)
    }
}

fn get_scheme() -> Scheme {
    let scheme = Scheme! {
        http.cookie:                     Bytes,
        http.host:                       Bytes,
        http.referer:                    Bytes,
        http.request.full_uri:           Bytes,
        http.request.method:             Bytes,
        http.request.uri:                Bytes,
        http.request.uri.path:           Bytes,
        http.request.uri.query:          Bytes,
        http.user_agent:                 Bytes,
        http.x_forwarded_for:            Bytes,
        ip.src:                          Ip,
        ip.geoip.asnum:                  Int,
        ip.geoip.country:                Bytes,
        ssl:                             Bool,
    };
    scheme
}

impl WirefilterPlugin {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new WAF Wirefilter plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for WirefilterPlugin {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::WirefilterPlugin
    }
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }

        let req_header = session.req_header();
        let headers = &req_header.headers;
        let mut allow = true;
    
        for item in self.restriction_expression_list.iter() {
            let expression = item.as_str();
            
            // Parse a Wireshark-like expression into an AST.
            let scheme = get_scheme();
            let ast = scheme.parse(expression).unwrap();
            // Compile the AST into an executable filter.
            let filter = ast.compile();

            // Set runtime field values to test the filter against.
            let mut ctx = ExecutionContext::new(&scheme);
            let _ = ctx.set_field_value(scheme.get_field("http.host").unwrap(), headers.contains_key("host"));
            let _ = ctx.set_field_value(scheme.get_field("http.referer").unwrap(), headers.contains_key("Referer"));
            let uri = req_header.uri.to_string();
            let _ = ctx.set_field_value(scheme.get_field("http.request.full_uri").unwrap(), uri.as_str());
            let _ = ctx.set_field_value(scheme.get_field("http.request.method").unwrap(),req_header.method.as_str());
            let _ = ctx.set_field_value(scheme.get_field("http.request.uri").unwrap(), req_header.uri.path_and_query().unwrap().as_str());
            let _ = ctx.set_field_value(scheme.get_field("http.request.uri.path").unwrap(), req_header.uri.path());
            let _ = ctx.set_field_value(scheme.get_field("http.request.uri.query").unwrap(), req_header.uri.query().unwrap_or_default());
            let _ = ctx.set_field_value(scheme.get_field("http.user_agent").unwrap(), USER_AGENT.as_str());
            let _ = ctx.set_field_value(scheme.get_field("http.x_forwarded_for").unwrap(), headers.contains_key("X-Forwarded-For"));
            let client_addr = session.client_addr().unwrap().to_string();
            let _ = ctx.set_field_value(scheme.get_field("ip.src").unwrap(), client_addr.as_str());
            //let _ = ctx.set_field_value(scheme.get_field("ip.geoip.asnum").unwrap(), headers.contains_key("Cookie"));
            //let _ = ctx.set_field_value(scheme.get_field("ip.geoip.country").unwrap(), headers.contains_key("Cookie"));
            let _ = ctx.set_field_value(scheme.get_field("ssl").unwrap(), headers.contains_key("ssl"));
            
            let matche_filter = filter.execute(&ctx).unwrap();
            println!("Filter matches: {:?}", matche_filter); // false
            info!(matche_filter, "client request restricted if filter find expression restriction in request data ");
            if matche_filter {allow = false}
        } 

        let mut message = String::from("");
        message.push_str("<html><head><title>Wire</title></head><body>");
        message.push_str("<h1>Request forbidden - ");
        message.push_str(allow.to_string().as_str());
        message.push_str("</h1>");
        message.push_str("0. uri = ");
        message.push_str(&req_header.uri.to_string());
        message.push_str("<br>");
        for (i, n) in headers.into_iter().enumerate() {
            let hn = &n.0.as_str();
            let hv = &n.1.to_str().unwrap();
            message.push_str(&(i+1).to_string());
            message.push_str(". ");
            message.push_str(hn);
            message.push_str(" = ");
            message.push_str(hv);
            message.push_str("<br>");
        }
        message.push_str("</body></html>");

        let mut forbidden_resp = self.forbidden_resp.clone();
        forbidden_resp.body = message.into();

        //let allow = false;
        if !allow {
            return Ok(Some(forbidden_resp));
        }
        return Ok(None);
    }
}
