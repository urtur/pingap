import useConfigStore from "../states/config";
import Loading from "../components/loading";
import FormEditor, {
  FormItem,
  FormItemCategory,
} from "../components/form-editor";

export default function BasicInfo() {
  const [initialized, config, update] = useConfigStore((state) => [
    state.initialized,
    state.data,
    state.update,
  ]);
  if (!initialized) {
    return <Loading />;
  }
  const arr: FormItem[] = [
    {
      id: "name",
      label: "Name",
      defaultValue: config.name,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "pid_file",
      label: "Pid File",
      defaultValue: config.pid_file,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upgrade_sock",
      label: "Upgrade Sock",
      defaultValue: config.upgrade_sock,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "threads",
      label: "Threads",
      defaultValue: config.threads,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "work_stealing",
      label: "Work Stealing",
      defaultValue: config.work_stealing,
      span: 6,
      category: FormItemCategory.CHECKBOX,
      options: [
        {
          label: "Yes",
          option: 1,
          value: true,
        },
        {
          label: "No",
          option: 0,
          value: false,
        },
        {
          label: "None",
          option: -1,
          value: null,
        },
      ],
    },
    {
      id: "user",
      label: "User",
      defaultValue: config.user,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "group",
      label: "Group",
      defaultValue: config.group,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "grace_period",
      label: "Grace Period",
      defaultValue: config.grace_period,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "graceful_shutdown_timeout",
      label: "Graceful Shutdown Timeout",
      defaultValue: config.graceful_shutdown_timeout,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "log_level",
      label: "Log Level",
      defaultValue: config.log_level,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upstream_keepalive_pool_size",
      label: "Upstream Keepalive Pool Size",
      defaultValue: config.upstream_keepalive_pool_size,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "webhook_type",
      label: "Webhook Type",
      defaultValue: config.webhook_type,
      span: 4,
      category: FormItemCategory.WEBHOOK_TYPE,
      options: ["normal", "wecom", "dingtalk"],
    },
    {
      id: "webhook",
      label: "Webhook Url",
      defaultValue: config.webhook,
      span: 8,
      category: FormItemCategory.TEXT,
    },
    {
      id: "sentry",
      label: "Sentry",
      defaultValue: config.sentry,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "pyroscope",
      label: "Pyroscope",
      defaultValue: config.pyroscope,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "error_template",
      label: "Error Template",
      defaultValue: config.error_template,
      span: 12,
      minRows: 8,
      category: FormItemCategory.TEXTAREA,
    },
  ];
  const onUpsert = async (name: string, data: Record<string, unknown>) => {
    return update("pingap", "basic", data);
  };
  return (
    <FormEditor
      title="Modify the basic configurations"
      description="The basic configuration of pingap mainly includes various configurations such as logs, graceful restart, threads, etc."
      items={arr}
      onUpsert={onUpsert}
    />
  );
}
