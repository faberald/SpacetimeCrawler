import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager, Link
from spacetime.client.IApplication import IApplication
from spacetime.client.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
import re, os
from time import time
import urllib2
import string

try:
    # For python 2
    from urlparse import urlparse, parse_qs
except ImportError:
    # For python 3
    from urllib.parse import urlparse, parse_qs


logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"
url_count = (set() 
    if not os.path.exists("successful_urls.txt") else 
    set([line.strip() for line in open("successful_urls.txt").readlines() if line.strip() != ""]))
MAX_LINKS_TO_DOWNLOAD = 3000

@Producer(ProducedLink, Link)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):

    def __init__(self, frame):
        self.starttime = time()
        # Set app_id <student_id1>_<student_id2>...
        self.app_id = "85723669_18289085_33112951"
        # Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
        # If Graduate studetn, change the UnderGrad part to Grad.
        self.UserAgentString = "IR W17 UnderGrad 85723669, 18289085, 33112951"
        
        self.frame = frame
        assert(self.UserAgentString != None)
        assert(self.app_id != "")
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def initialize(self):
        self.count = 0
        l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
        print l.full_url
        self.frame.add(l)

    def update(self):
        for g in self.frame.get_new(OneUnProcessedGroup):
            print "Got a Group"
            outputLinks, urlResps = process_url_group(g, self.UserAgentString)
            for urlResp in urlResps:
                if urlResp.bad_url and self.UserAgentString not in set(urlResp.dataframe_obj.bad_url):
                    urlResp.dataframe_obj.bad_url += [self.UserAgentString]
            for l in outputLinks:
                if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
                    lObj = ProducedLink(l, self.UserAgentString)
                    self.frame.add(lObj)
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def shutdown(self):
        print "downloaded ", len(url_count), " in ", time() - self.starttime, " seconds."
        pass

def save_count(urls):
    global url_count
    urls = set(urls).difference(url_count)
    url_count.update(urls)
    if len(urls):
        with open("successful_urls.txt", "a") as surls:
            surls.write(("\n".join(urls) + "\n").encode("utf-8"))

def process_url_group(group, useragentstr):
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)
    save_count(successfull_urls)
    return extract_next_links(rawDatas), rawDatas
    
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
    outputLinks = list()
    '''
    rawDatas is a list of objs -> [raw_content_obj1, raw_content_obj2, ....]
    Each obj is of type UrlResponse  declared at L28-42 datamodel/search/datamodel.py
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.

    Suggested library: lxml
    '''
    print len(rawDatas)
    for i in rawDatas:
        if i.is_redirected:
            url = i.final_url
        else:
            url = i.url
        if  is_valid(url) and len(i.error_message) == 0 and string.atoi(i.http_code) < 400:
            conn = urllib2.urlopen(url)
            page = conn.read()
            doc = html.fromstring(page)
            doc.make_links_absolute(url)
            abslinks = list(doc.iterlinks())
            for v in range(len(abslinks)):
                el,attr,link,pos = abslinks[v]
                if is_valid(link):
                    # try:
                    #     check_http_code = urllib2.urlopen(link)
                    # except urllib2.HTTPError as e:
                    #     print "HTTPError"
                    # except urllib2.URLError as e:
                    #     print "URLError"
                    # else:
                    i.out_links.add(link)
            outputLinks.extend(list(i.out_links))
        else:
            i.bad_url = True


    # for i in rawDatas:
    #     if is_valid(i.url) and atoi(i.http_code) < 300:
    #         print i.http_code
    #         outputLinks.append(i.url)

    # print outputLinks
    return outputLinks

def is_valid(url):
    '''
    Function returns True or False based on whether the url has to be downloaded or not.
    Robot rules and duplication rules are checked separately.

    This is a great place to filter out crawler traps.
    '''
    # check wheter the url is in abosute form
    file = open("bad_urls.txt", 'w')
    print url
    parsed = urlparse(url)
    if parsed.scheme not in set(["http", "https"]):
        return False

    if "calendar.ics.uci.edu" in parsed.hostname:
        return False

    # long no meaning url
    if len(url) > 300:
        return False

    # if url == "https://duttgroup.ics.uci.edu/doku.php/home?do=media&ns=":
    #     return False

    # use regular expression to avoid reapting directories
    # https://support.archive-it.org/hc/en-us/community/posts/115000330506-How-to-avoid-crawler-traps-when-archiving-YouTube-videos
    if re.match(r"^.*?(/.+?/).*?\1.*$|^.*?/(.+?/)\2.*$", parsed.path.lower()):
        file.write(url+"\n")
        return False

    #check repeated_url using token
    token_dict = defaultdict(int)
    token_list = re.split("/", parsed.geturl())
        
    for token in token_list:
        token_dict[token] += 1

    sorted_dict = sorted(token_dict.items(), key = lambda t: t[1], reverse = True)
    for key,value in sorted_dict:
        if value >= 3:
            return False

    # if re.match(r"^.*?(.+_).*?\1.*$|^.*?/(.+?_)\2.*$", parsed.path.lower()):
    #     return False

    if re.match(r"^.*(_doku.php_|.jpg|&ns|_amp|.png){1}.*$", parsed.query.lower()) or re.match(r"^.*(_doku.php_|.jpg|&ns|_amp|.png){1}.*$", parsed.path.lower()):
        return False

    if re.match(r"^.*(/extreme_recruit.php|/grad){2}.*$", parsed.query.lower()):

        return False

    if re.match(r"^.*(.php/).*$", parsed.path.lower()):
        return False

    # there is a better version 
    if re.match(r"^.*(//).*$", parsed.path.lower()):
        return False

    if re.match(r"^.*(qa_petitions/).*$", parsed.path.lower()):
        return False

    if re.match(r"^.*(qa_graduation/).*$", parsed.path.lower()):
        return False

    if re.match(r"^.*(add_drop_changeoption/).*$", parsed.path.lower()):
        return False

    if re.match(r"^.*(grade_options/).*$", parsed.path.lower()):
        return False

    # http://www.ics.uci.edu/ugrad/index/grad/funding/policies/computing/account.php
    if re.match(r"^.*(/ugrad/index).*$", parsed.path.lower()):
        return False

    if re.match(r"^.*(/grad/index).*$", parsed.path.lower()):
        return False

    if re.match(r"^.*(afg).*$", parsed.query.lower()):
        return False

    # avoid query that contains /bin|/img|/logos|/socialmedia
    if re.match("^.*(/bin|/img|/logos|/socialmedia){4}.*$", parsed.query.lower()):
        return False

    # make sure the url does not direct to a file 
    if re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv"\
            + "|rm|smil|wma|zip|rar|gz|lif|php)$", url.lower()):
        return False

    try:
        return ".ics.uci.edu" in parsed.hostname \
            and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv"\
            + "|rm|smil|wmv|swf|wma|zip|rar|gz|lif|php)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
