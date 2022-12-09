# IDS

IDS for detecting mDNS timing anomalies


#### Train on clean traffic:

```bash
sudo ./ids -i wlan0 -m train -c
```

#### Train on malicious traffic:

```bash
sudo ./ids -i wlan0 -m train
```

#### Run in IDS mode:

```bash
sudo ./ids -i wlan0 -m ids
```
