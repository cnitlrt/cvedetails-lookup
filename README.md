## Install
```bash
pip3 install -r requirements.txt
```
## Usage
```
usage: getcve.py [-h] [--vendor VENDOR] --product PRODUCT --version VERSION [--csv <output-filename>] [--display-csv]
```
### Example
```bash
python3 getcve.py --product busybox --version 1.30.1
```

![image-20231218165230628](image/image-20231218165230628.png)

## References

```
https://github.com/koutto/cvedetails-lookup/blob/master/cvedetails-lookup.py
```
