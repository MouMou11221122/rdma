### env
```
machine 50:
    RNIC: BlueField-3 integrated ConnectX-7

machine 52:
    RNIC: BlueField-3 integrated ConnectX-7
```

### show RNIC status
```
ibv_devinfo
ibstat
```

### utilities to test rdma connection and bandwidth
client:
    ib_read_bw/ib_write_bw -d mlx5_0/mlx5_1

server:
    ib_read_bw/ib_write_bw 10.10.10.1/10.10.10.2 -d mlx5_0/mlx5_1 --report_gbits

* [Reference](https://blog.csdn.net/essencelite/article/details/143898032)

