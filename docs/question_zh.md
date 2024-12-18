---
description: Pingap 常见问题
---

## Location指定Host请求头

有些http服务是多个服务共用端口，而通过请求头的`Host`来区分服务的，因此对于此类场景需要在location的配置中设置转发的请求头`Host`。

## Upstream的地址设置

Uptream的地址是基于IP+端口，若未设置端口则使用`80`，需要注意若地址使用的是域名，默认的服务发现方式只在初始化时将该域名解析为对应IP(若有多个ip则添加多个地址)，后续IP变化无法实时感知。若IP会变化则需使用dns的服务发现方式。

## Theads的配置

Pingap的线程设置是按server分开的(默认为1)，可以单独的设置每个server对应的线程数，或者在基础配置中设置，设置之后每个server若未单独指定，则按基础设置中的值一致。若希望与CPU核数一致，则设置为0即可。

## Upstream为HTTPS

如果upstream是使用https提供服务的，需要设置其对应的sni，以及上游节点地址如果不指定端口，则使用https默认的`443`端口。

## 同一端口提供不同域名的https服务

若同一server需要提供不同的https域名服务，则将证书单独配置，后设置服务`使用应用的全局证书`即可。
