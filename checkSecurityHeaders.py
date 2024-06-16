import requests
import csv
import ssl
import socket

#設定該Header通過條件的值
def is_secure_header(header, value):
    secure_headers = {
        'X-Frame-Options': lambda v: v in ['DENY', 'SAMEORIGIN'],
        'X-XSS-Protection': lambda v: v == '1; mode=block',
        'Strict-Transport-Security': lambda v: 'max-age' in v and int(v.split('max-age=')[1].split(';')[0]) >= 31536000,
        'Referrer-Policy': lambda v: v in ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin', 'origin', 'origin-when-cross-origin'],
        'X-Content-Type-Options': lambda v: v == 'nosniff',
        'Content-Security-Policy': lambda v: True,
        'Feature-Policy': lambda v: 'geolocation' in v and 'microphone' in v and 'camera' in v,
        'Permissions-Policy': lambda v: True if v else False 
    }
    
    return secure_headers.get(header, lambda v: False)(value)
  
#要檢查的Headers
def check_security_headers(urls):
    headers_to_check = [
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Referrer-Policy',
        'X-Content-Type-Options',
        'Content-Security-Policy',
        'Feature-Policy',
        'Permissions-Policy'
    ]
    
    results = []

    for url in urls:
        try:
            response = requests.get(url)
            headers = response.headers

            # 除錯用
            # Print headers to screen(for debug)
            print(f"\nHeaders for {url}:")
            for header, value in headers.items():
                print(f"{header}: {value}")

            # 檢查與判斷
            result = [url]
            for header in headers_to_check:
                if header in headers and is_secure_header(header, headers[header]):
                    result.append("OK")
                else:
                    result.append("NO")
            
            # Check for Forward Secrecy
            hostname = url.split("//")[-1].split("/")[0]
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=hostname,
            )
            conn.connect((hostname, 443))
            cipher = conn.cipher()
            conn.close()
            
            if "DHE" in cipher[0] or "ECDHE" in cipher[0]:
                result.append("OK")
            else:
                result.append("NO")
                    
            results.append(result)
        except requests.RequestException as e:
            print(f"Error accessing {url}: {e}")
            results.append([url] + ["ERROR"] * (len(headers_to_check) + 1))
        except Exception as e:
            print(f"Error checking Forward Secrecy for {url}: {e}")
            results.append([url] + ["ERROR"] * (len(headers_to_check) + 1))
    
    return results

def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.read().splitlines()
    return urls

def write_results_to_csv(results, output_file):
    headers = [
        'URLs', 
        'X-Frame-Options', 
        'X-XSS-Protection', 
        'Strict-Transport-Security', 
        'Referrer-Policy', 
        'X-Content-Type-Options', 
        'Content-Security-Policy', 
        'Feature-Policy', 
        'Permissions-Policy', 
        'Forward Secrecy'
    ]
    
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(results)

def main(input_file, output_file):
    urls = read_urls_from_file(input_file)
    results = check_security_headers(urls)
    write_results_to_csv(results, output_file)
    print(f"Results have been written to {output_file}")

if __name__ == "__main__":
    input_file = 'urls.txt'  # 請將這裡替換為你的輸入檔案
    output_file = 'results.csv'  # 請將這裡替換為你希望輸出的檔案名
    main(input_file, output_file)
