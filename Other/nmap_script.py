#!/usr/bin/env python3
"""
Usage:
    python3 nmap_to_excel.py scan1.xml scan2.xml ...

Description:
    - Parses each Nmap XML file and creates a CSV-like DataFrame for it
    - Collects all DataFrames into an Excel workbook, one sheet per scan
    - Applies basic header formatting and column sizing
"""

import sys
import re
import os
import xml.etree.ElementTree as ET
import pandas as pd

# ---------- NATURAL SORT HELPERS ----------
def atoi(text):
    return int(text) if text.isdigit() else text

def natural_keys(text):
    """Sorts ports in human order, e.g. tcp21 < tcp111 < tcp443"""
    return [atoi(c) for c in re.split(r'(\d+)', text)]


# ---------- PARSE SINGLE NMAP XML ----------
def parse_nmap_xml(xml_path):
    root = ET.parse(xml_path).getroot()
    results = {}
    open_ports = []

    for host in root.findall('.//host'):
        ip = host.find('address').attrib.get('addr', '')
        ptr = ''
        try:
            extraports = host.find('.//ports/extraports').attrib['count']
            extraports += ' ' + host.find('.//ports/extraports').attrib['state']
        except Exception:
            extraports = ''

        # PTR hostname
        for hostname in host.findall('.//hostname'):
            if hostname.attrib.get('type') == 'PTR':
                ptr = hostname.attrib.get('name', '')

        # Open ports
        for port_el in host.findall('.//port'):
            if port_el.find('state').attrib.get('state') == 'open':
                if ip not in results:
                    results[ip] = {'ports': {}}
                proto = port_el.attrib.get('protocol', '')
                portid = port_el.attrib.get('portid', '')
                port = f"{proto}{portid}"
                open_ports.append(port)

                service_el = port_el.find('service')
                if service_el is not None and service_el.attrib.get('name'):
                    product = service_el.attrib.get('product', 'open')
                    version = service_el.attrib.get('version')
                    service = f"{product} {version}" if version else product
                else:
                    service = 'open'

                results[ip]['ports'][port] = service

        if ip in results:
            results[ip]['PTR'] = ptr
            results[ip]['Other Ports'] = extraports

    ports = sorted(set(open_ports), key=natural_keys)

    # Build DataFrame
    headers = ['ipaddress', 'PTR', 'Other Ports'] + ports
    rows = []
    for ip, data in results.items():
        row = [ip, data.get('PTR', ''), data.get('Other Ports', '')]
        for port in ports:
            row.append(data['ports'].get(port, ''))
        rows.append(row)

    df = pd.DataFrame(rows, columns=headers)
    return df


# ---------- MAIN COMBINER ----------
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_to_excel.py <scan1.xml> <scan2.xml> ...")
        sys.exit(1)

    out_xlsx = "nmap_results.xlsx"
    writer = pd.ExcelWriter(out_xlsx, engine="xlsxwriter")
    workbook = writer.book
    workbook.formats[0].set_font_size(9)

    header_fmt = workbook.add_format({
        'font_color': 'black',
        'bg_color': '#cccccc',
        'bold': True
    })

    for xmlfile in sys.argv[1:]:
        df = parse_nmap_xml(xmlfile)
        sheet_name = os.path.splitext(os.path.basename(xmlfile))[0][:31]  # Excel sheet limit
        df.to_excel(writer, sheet_name=sheet_name, startrow=1, index=False, header=False)

        worksheet = writer.sheets[sheet_name]

        # Apply header formatting
        for col_num, value in enumerate(df.columns):
            worksheet.write(0, col_num, value, header_fmt)
            worksheet.set_column(col_num, col_num, 18)

    writer._save()  # for xlsxwriter engine
    print(f"[+] Combined Excel workbook saved to {out_xlsx}")


if __name__ == "__main__":
    main()
