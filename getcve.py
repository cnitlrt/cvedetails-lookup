import requests
import re
import prettytable as pt
import colored
import argparse
import bs4

from tqdm import tqdm
def colorize(string, color=None, highlight=None, attrs=None):
    """Apply style on a string"""
    # Colors list: https://pypi.org/project/colored/
    return colored.stylize(
        string,
        (colored.fg(color) if color else "")
        + (colored.bg(highlight) if highlight else "")
        + (colored.attr(attrs) if attrs else ""),
    )
def table(columns, data, hrules=True):
    """Print a table"""
    columns = map(lambda x: colorize(x, attrs="bold"), columns)
    table = pt.PrettyTable(
        hrules=pt.ALL if hrules else pt.FRAME, field_names=columns
    )
    for row in data:
        table.add_row(row)
    table.align = "l"
    print(table)
def color_cvss(cvss):
    """Attribute a color to the CVSS score"""
    cvss = float(cvss)
    if cvss < 3:
        color = "green_3b"
    elif cvss <= 5:
        color = "yellow_1"
    elif cvss <= 7:
        color = "orange_1"
    elif cvss <= 8.5:
        color = "dark_orange"
    else:
        color = "red"
    return color
def cve_check():
    version = args.version
    product = args.product
    burp0_url = f"https://www.cvedetails.com:443/version-search.php?page=1&vendor=&product={product}&version={version}"
    burp0_headers = {"Sec-Ch-Ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"", "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "https://www.cvedetails.com/version-search.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    x = requests.get(burp0_url, headers=burp0_headers)
    soup = bs4.BeautifulSoup(x.text,"html.parser")
    m = (soup.find("h1").findAll("a"))
    if len(m) == 0:
        return False
    vendor_id = re.findall(r'vendor/(\d*)',m[0]["href"])[0]
    product_id = re.findall(r'version-list/\d*/(\d*)',m[1]["href"])[0]
    version_id = re.findall(r'version/(\d*)/',m[2]["href"])[0]
    url = f"https://www.cvedetails.com/vulnerability-list/vendor_id-{vendor_id}/product_id-{product_id}/version_id-{version_id}/"
    x = requests.get(url, headers=burp0_headers)
    soup = bs4.BeautifulSoup(x.text,"html.parser")
    m = soup.findAll("h3")
    cve_id = []
    url_list = []
    for x in m:
        y = x.findAll("a")
        for m in y:
            url_list.append("https://www.cvedetails.com"+m["href"])
            n = re.findall(r"/cve/(.*)/",m["href"])
            cve_id.append(n[0])
    m = (soup.findAll('div', {'class': 'cvssbox'}))
    cvss_list = []
    for x in m:
        cvss_list.append(x.text)
    m = soup.findAll('div',{"class":"cvesummarylong"})
    cvesummary = []
    for x in m:
        cvesummary.append(x.text)
    m = soup.findAll("div",{"data-tsvfield":"publishDate"})
    data_list = []
    for x in m:
        data_list.append(x.text)
    assert len(cve_id) == len(cvss_list) == len(data_list) == len(url_list) == len(cvesummary)
    columns = ["ID", "CVSS", "Date", "Description","URL"]
    line_list = []
    for i in range(len(cve_id)):
        line = [cve_id[i],colorize(cvss_list[i], color=color_cvss(cvss_list[i]), attrs="bold"),data_list[i],cvesummary[i],url_list[i]]
        line_list.append(line)
    table(columns, line_list, hrules=True)
        
def kernel_check():
    version = args.version
    product = "linux kernel"
    burp0_url = f"https://www.cvedetails.com:443/version-search.php?page=1&vendor=&product={product}&version={version}"
    burp0_headers = {"Sec-Ch-Ua": "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"", "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "https://www.cvedetails.com/version-search.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    x = requests.get(burp0_url, headers=burp0_headers)
    x = x.text
    print("Vendor, Product, Version Search" not in x)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--vendor", help="Vendor (optional)", action="store", dest="vendor", default=""
    )
    parser.add_argument(
        "--product", help="Product (required)", action="store", required=True, dest="product"
    )
    parser.add_argument(
        "--version", help="Version (required)", action="store", required=True, dest="version"
    )
    parser.add_argument(
        "--csv",
        help="Output as CSV file (fields separated by semicolon)",
        action="store",
        metavar="<output-filename>",
        dest="csv",
    )
    parser.add_argument(
        "--display-csv",
        help="Display CSV data at the end",
        action="store_true",
        dest="displaycsv",
    )
    args = parser.parse_args()
    cve_check()
    