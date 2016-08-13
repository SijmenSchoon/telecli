class Request:
    def __init__(self, token, type, flags, datacenter, complete_func, quick_ack_func):
        self.message_id = 0
        self.message_seq_no = 0
        self.connection_token = 0
        self.retry_count = 0
        self.failed_by_salt = False
        self.completed = False
        self.cancelled = False
        self.is_init_request = False
        self.serialized_length = 0
        self.start_time = 0
        self.min_start_time = 0
        self.last_resend_time = 0
        self.server_failure_count = 0
        self.raw_request = None
        self.rpc_request = None
        self.responds_to_message_ids = []

        self.request_token = token
        self.connection_type = type
        self.request_flags = flags
        self.datacenter_id = datacenter
        self.on_complete_func = complete_func
        self.on_quick_ack_func = quick_ack_func

    def add_respond_message_id(self, id):
        self.responds_to_message_ids.append(id)

    def responds_to_message_id(self, id):
        return self.message_id == id or id in self.responds_to_message_ids

    def clear(self, clear_time):
        self.message_id = 0
        self.message_seq_no = 0
        self.connection_token = 0
        if clear_time:
            self.start_time = 0
            self.min_start_time = 0

    def on_complete(self, result, error):
        if self.on_complete_func is not None and (result is not None or error is not None):
            self.on_complete_func(result, error)

    def on_quick_ack(self):
        if self.on_quick_ack_func is not None:
            self.on_quick_ack()
