datacenter = "localhost",
data_dir = "/consul/data"
log_level = "err"

server = true
bootstrap_expect = 1
ui = true

bind_addr = "{{ GetPrivateInterfaces | include \"network\" \"10.0.0.0/8\" | attr \"address\" }}"
client_addr = "0.0.0.0"

ports {
  dns = 53
}