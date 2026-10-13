# alc-auth-worker

ログインの内部口と機械用資格情報を DB (alc_api) で扱う Rust の Cloudflare Worker。auth-worker から Service Binding でだけ呼ばれる (workers_dev = false、route なし)。

Refs ohishi-exp/rust-leave-worker#1
