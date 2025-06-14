### env
```
machine 50:
    RNIC: BlueField-3 integrated ConnectX-7

machine 52:
    RNIC: BlueField-3 integrated ConnectX-7
```

### show detail RNIC status
```
ibv_devinfo -v
ibstat
```

### utilities to test rdma connection and bandwidth
client:
    ib_read_bw/ib_write_bw 10.10.10.1/10.10.10.2 -d mlx5_0/mlx5_1 --report_gbits

server:
    ib_read_bw/ib_write_bw -d mlx5_0/mlx5_1 --report_gbits

### utilities to test rdma connection and latency
```
client:
    ib_write_lat       
        -d mlx5_1     # RDMA device
        -i 1          # Port num
        -n 10         # Iterations
        -s 1073741824 # Bytes
        10.10.10.2    # Remote IP
server:
    ib_write_lat       
        -d mlx5_1     # RDMA device
        -i 1          # Port num
        -n 10         # Iterations
        -s 1073741824 # Bytes
```
### subnet manager
A rdma physical connection binded by a subnet manager. Subnet manager runs on one of machine.

### network manager
```
nmtui
```

### add ip to device
sudo ip addr add <ip/subnet> dev <dev_name>
sudo ip link set <dev_name> up

### bind a subset manager to port
ibstat -p
sudo opensm -B -g <dev_guid>

* [Reference](https://blog.csdn.net/essencelite/article/details/143898032)

