#!/usr/bin/env python3
"""
ParamSpider: Parameter miner for humans
A tool to find parameters from web archives of the entered domain.
Converted from the original ParamSpider tool by 0xKayala
"""

import requests
import re
import argparse
import os
import sys
import time
import random
import warnings
import errno
from urllib.parse import unquote

# Suppress warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)

start_time = time.time()

class ParamSpider:
    def __init__(self):
        self.user_agent_list = [
            # Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
            'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
            # Firefox
            'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
            'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',
            'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
            'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'
        ]

    def display_banner(self):
        """Display the ParamSpider banner"""
        banner = r"""
   
            ___                               _    __       
           / _ \___ ________ ___ _  ___ ___  (_)__/ /__ ____
          / ___/ _ `/ __/ _ `/  ' \\(_-</ _ \/ / _  / -_) __/
         /_/   \_,_/_/  \_,_/_/_/_/___/ .__/_/\_,_/\__/_/   
                                     /_/                   
                               
                               - coded with <3 by Devansh Batham 
        """
        print(banner)

    def connector(self, url, retries=3):
        """
        Connect to the web archive and fetch data with retry mechanism
        """
        result = False
        retry = True
        retry_count = 0
        
        while retry and retry_count <= retries:
            user_agent = random.choice(self.user_agent_list)
            headers = {'User-Agent': user_agent}
            
            try:
                response = requests.get(url, headers=headers, timeout=60)
                result = response.text
                retry = False
                response.raise_for_status()
                
            except requests.exceptions.ConnectionError as e:
                retry = False
                print("\u001b[31;1mCan not connect to server. Check your internet connection.\u001b[0m")
                
            except requests.exceptions.Timeout as e:
                retry = True
                print("\u001b[31;1mOOPS!! Timeout Error. Retrying in 2 seconds.\u001b[0m")
                time.sleep(2)
                
            except requests.exceptions.HTTPError as err:
                retry = True
                print(f"\u001b[31;1m {err}. Retrying in 2 seconds.\u001b[0m")
                time.sleep(2)
                
            except requests.exceptions.RequestException as e:
                retry = True
                print(f"\u001b[31;1m {e} Can not get target information\u001b[0m")
                print("\u001b[31;1mIf you think this is a bug or unintentional behaviour. Report here : https://github.com/0xKayala/ParamSpider/issues\u001b[0m")
                
            except KeyboardInterrupt as k:
                retry = False
                print("\u001b[31;1mInterrupted by user\u001b[0m")
                raise SystemExit(k)
                
            finally:
                retry_count += 1
                
        return result, retry

    def param_extract(self, response, level, black_list, placeholder):
        """
        Function to extract URLs with parameters (ignoring the black list extension)
        """
        # Using raw string to avoid invalid escape sequence warning
        parsed = list(set(re.findall(r'.*?:\/\/.*\?.*=[^$]', response)))
        final_uris = []
        
        for i in parsed:
            delim = i.find('=')
            second_delim = i.find('=', i.find('=') + 1)
            
            if len(black_list) > 0:
                words_re = re.compile("|".join(black_list))
                if not words_re.search(i):
                    final_uris.append((i[:delim+1] + placeholder))
                    if level == 'high':
                        final_uris.append(i[:second_delim+1] + placeholder)
            else:
                final_uris.append((i[:delim+1] + placeholder))
                if level == 'high':
                    final_uris.append(i[:second_delim+1] + placeholder)

        return list(set(final_uris))

    def save_func(self, final_urls, outfile, domain):
        """
        Save the extracted URLs to a file
        """
        if outfile:
            if "/" in outfile:
                filename = f'{outfile}'
            else:
                filename = f'output/{outfile}'
        else:
            filename = f"output/{domain}.txt"
        
        if os.path.exists(filename):
            os.remove(filename)

        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
        
        for i in final_urls:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(i + "\n")

    def run(self, domain, subs=True, level=None, exclude=None, output=None, placeholder="FUZZ", quiet=False, retries=3):
        """
        Main function to run ParamSpider
        """
        # Delay to ensure banner appears first
        time.sleep(2)
        
        # Display banner
        self.display_banner()
        
        # Build URL for web archive
        if subs == True or subs == "True":
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        else:
            url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        
        # Fetch data from web archive
        response, retry = self.connector(url, retries)
        if response == False:
            return
        
        response = unquote(response)
        
        # Process exclusions
        black_list = []
        if exclude:
            if "," in exclude:
                black_list = exclude.split(",")
                for i in range(len(black_list)):
                    black_list[i] = "." + black_list[i]
            else:
                black_list.append("." + exclude)
        
        if exclude:
            print(f"\u001b[31m[!] URLS containing these extensions will be excluded from the results   : {black_list}\u001b[0m\n")
        
        # Extract parameters
        final_uris = self.param_extract(response, level, black_list, placeholder)
        
        # Save results
        self.save_func(final_uris, output, domain)
        
        # Display results
        if not quiet:
            print("\u001b[32;1m")
            print('\n'.join(final_uris))
            print("\u001b[0m")
        
        print(f"\n\u001b[32m[+] Total number of retries:  {retries}\u001b[31m")
        print(f"\u001b[32m[+] Total unique urls found : {len(final_uris)}\u001b[31m")
        
        if output:
            if "/" in output:
                print(f"\u001b[32m[+] Output is saved here :\u001b[31m \u001b[36m{output}\u001b[31m")
            else:
                print(f"\u001b[32m[+] Output is saved here :\u001b[31m \u001b[36moutput/{output}\u001b[31m")
        else:
            print(f"\u001b[32m[+] Output is saved here   :\u001b[31m \u001b[36moutput/{domain}.txt\u001b[31m")
        
        print("\n\u001b[31m[!] Total execution time      : %ss\u001b[0m" % str((time.time() - start_time))[:-12])


def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description='ParamSpider a parameter discovery suite')
    parser.add_argument('-d', '--domain', help='Domain name of the target [ex : hackerone.com]', required=True)
    parser.add_argument('-s', '--subs', help='Set False for no subs [ex : --subs False ]', default=True)
    parser.add_argument('-l', '--level', help='For nested parameters [ex : --level high]')
    parser.add_argument('-e', '--exclude', help='extensions to exclude [ex --exclude php,aspx]')
    parser.add_argument('-o', '--output', help='Output file name [by default it is \'domain.txt\']')
    parser.add_argument('-p', '--placeholder', help='The string to add as a placeholder after the parameter name.', default="FUZZ")
    parser.add_argument('-q', '--quiet', help='Do not print the results to the screen', action='store_true')
    parser.add_argument('-r', '--retries', help='Specify number of retries for 4xx and 5xx errors', default=3, type=int)
    
    args = parser.parse_args()
    
    # Create ParamSpider instance and run
    spider = ParamSpider()
    spider.run(
        domain=args.domain,
        subs=args.subs,
        level=args.level,
        exclude=args.exclude,
        output=args.output,
        placeholder=args.placeholder,
        quiet=args.quiet,
        retries=args.retries
    )


if __name__ == "__main__":
    main()