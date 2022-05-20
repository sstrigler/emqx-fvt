# -*- encoding: utf-8 -*-
"""
@File    : screenshot.py
@Time    : 2022/3/3 10:42 pm
@Author  : Dn_By
@Software: PyCharm
"""
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
import requests
import time
import logging
import json
import os
import re
import urllib3

urllib3.disable_warnings()

HTTP_HEADER = {
            'Connection': 'keep-alive',
            'Accept-Language': 'en-US',
            'ontent-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
        }

XMETER_USER = "xfypp@sina.com"
REPORT_ID = ""
LOG_PATH = "./data/log"
IMAGE_FILE_PATH = "./data/image"

XMETER_ELEMENT_VALUE = ".echarts-for-react"
# GRAFANA_ELEMENT_VALUE = "[class='graph-legend-alias pointer']"
GRAFANA_ELEMENT_VALUE = "[class='panel-title-text drag-handle']"


logger = logging.getLogger(__name__)
formatter = logging.Formatter('[%(asctime)s] - %(filename)s] - %(lineno)d - %(levelname)s: %(message)s')
waring = logging.WARNING
debug = logging.DEBUG
logger.setLevel(level=debug)
console = logging.StreamHandler()
console.setLevel(level=debug)
console.setFormatter(formatter)
logger.addHandler(console)


def check_filepath(file_path):
    if not os.path.exists(file_path):
        os.makedirs(file_path)


def log_to_file():
    log_filename = os.path.join(LOG_PATH, '{}.log'.format(time.strftime("%Y%m%d_%H%M%S")))
    console_file = logging.FileHandler(log_filename, encoding='utf-8')
    console_file.setLevel(level=debug)
    console_file.setFormatter(formatter)
    logger.addHandler(console_file)


def start():
    check_filepath(LOG_PATH)
    check_filepath(IMAGE_FILE_PATH)
    log_to_file()


def firefox_driver():
    """ Firefox """
    options = webdriver.FirefoxOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument('ignore-certificate-errors')

    driver = webdriver.Firefox(executable_path='./geckodriver',
                               firefox_options=options)

    return driver


def login(driver, ip):
    """ login """
    url = "https://{}/login.html".format(str(ip))
    logger.info("Login_URL: {}".format(url))
    driver.get(url)
    WebDriverWait(driver=driver, timeout=90, poll_frequency=0.5) \
        .until(lambda diver: driver.find_element_by_css_selector("[name=form-alias]")).send_keys(XMETER_USER)
    driver.find_element_by_css_selector("[type=password]").send_keys(XMETER_USER)
    driver.find_element_by_css_selector("#submitLogin").click()
    time.sleep(3)


def download_test_results(file_links: list, document_path):
    for link in file_links:
        file_name = link.split('/')[-1]
        logger.info("Downloading file:%s" % file_name)

        test_results_file_path = os.path.join(document_path, file_name)

        r = requests.get(link, stream=True, verify=False)

        try:
            # download started  r.content   r.iter_content
            with open(test_results_file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
            logger.info("%s downloaded!\n" % file_name)

        except IOError:
            logger.error("File download failed")
            return False

    logger.info("All report downloaded!")
    return True


def scroll(driver, report_type: bool):
    """
    :param driver: WebDriver
    :param report_type: True(performance_report)、False(emqx_cluster)
    :return:
    """
    # width: height 1920: 2510、1920: 852
    report_proportion = round(1900 / 2700, 3)
    emqx_cluster_proportion = round(1900 / 1300, 3)
    # use javascript get the width and height of the page
    width = driver.execute_script("return document.documentElement.scrollWidth")
    # height = driver.execute_script("return document.documentElement.scrollHeight")
    if report_type:
        report_height = int(width) // report_proportion
        logger.info("Browser width and height[%s: %s]" % (width, report_height))
        driver.set_window_size(width, report_height)
    else:
        emqx_cluster_height = int(width) // emqx_cluster_proportion
        logger.info("Browser width and height[%s: %s]" % (width, emqx_cluster_height))
        driver.set_window_size(width, emqx_cluster_height)


def lazy_scroll(driver):
    js_height = "return document.body.clientHeight"
    height = driver.execute_script(js_height)

    k = 1
    while True:
        if k * 500 < height:
            js_move = "window.scrollTo(0,{})".format(k * 500)
            driver.execute_script(js_move)
            time.sleep(0.2)
            height = driver.execute_script(js_height)
            k += 1
        else:
            break

    time.sleep(3)
    # Get the width and height of the page with js
    width = driver.execute_script("return document.documentElement.scrollWidth")
    height = driver.execute_script("return document.documentElement.scrollHeight")
    driver.set_window_size(width, height)
    logger.info("Scroll TO Browser width and height[%s: %s]" % (width, height))
    logger.info("Page loaded successfully, start downloading ...... ")


def re_http_path(link: str):
    re_http = r'(ht|f)tp(s?)\:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(\/?)([a-zA-Z0-9\-\.\?\,\'\/\\\+&%\$#_]*)?'
    url = re.search(re_http, link, re.M | re.I).group()
    return url


def re_host(http_path: str):
    re_ip = r"((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))"
    host = re.search(re_ip, http_path).group()
    return host


def node_grafana(xmeter_ip, test_id, token):
    monitors_url = "https://{}/commercial_service/rest/applications/testrun/{}/monitors".format(xmeter_ip, test_id)
    HTTP_HEADER["xmeter-authorization"] = token
    HTTP_HEADER["host"] = xmeter_ip
    try:
        response = requests.get(monitors_url, headers=HTTP_HEADER, verify=False)
        response_body = dict(response.json())
        emqx_nodes = []
        grafana_monitors = []
        for node, grafana in response_body.items():
            emqx_nodes.append(node)
            grafana_monitors.append(grafana)

        logger.info("get monitors url: {}".format(monitors_url))
        logger.info("emqx cluster node ip address: {}".format(emqx_nodes))
        logger.info("emqx cluster node grafana monitor url: {}".format(grafana_monitors))
        return emqx_nodes, grafana_monitors
    except Exception as ec:
        logger.error("Failed to get the resource usage report address of each node in the emq cluster: {}".format(ec))
        return False


def test_info(xmeter_ip, test_id, token):
    HTTP_HEADER["host"] = xmeter_ip
    HTTP_HEADER["xmeter-authorization"] = token
    run_test_info_url = "https://{}/commercial_service/rest/testcase/testrun/{}" \
        .format(xmeter_ip, test_id)
    try:
        response = requests.get(run_test_info_url, headers=HTTP_HEADER, verify=False)
        response_body = dict(response.json())

        # Get test start time、test end time、EmqxClusterNode
        test_case_information = {
            "asteroid_base_url": response_body['asteroidBaseUrls'][0],
            "start_time": int(response_body.get("startTimeAsLong")),
            "end_time": int(response_body['endTimeAsLong']) + 20000,
            "grafana_report_addr": response_body['reports'][0]['reportAddr'],
            "conf_other_para": json.loads(response_body['confOtherPara'])
        }

        logger.info("Get test report details: {}".format(run_test_info_url))
        logger.info("test case information: {}".format(test_case_information))
        return test_case_information
    except Exception as ec:
        logger.error("Failed to get test report details: {}".format(ec))
        return False


def visit_report_page(page_url, driver, report_type=True):
    """ visit page """
    if report_type:
        css_value = XMETER_ELEMENT_VALUE
    else:
        css_value = GRAFANA_ELEMENT_VALUE

    driver.get(page_url)
    logger.info("visit page url: {}".format(page_url))
    WebDriverWait(driver=driver, timeout=60, poll_frequency=0.5) \
        .until(lambda diver: driver.find_elements_by_css_selector(css_value))
    time.sleep(3)
    lazy_scroll(driver=driver)


def save_report_screenshot(page_url, driver, screenshot_name, report_type):
    """ take screenshot """
    visit_report_page(page_url=page_url, driver=driver, report_type=report_type)
    report_image_path = os.path.join(IMAGE_FILE_PATH, screenshot_name)
    driver.save_screenshot(report_image_path)

    logger.info("Save Screenshot: {}".format(screenshot_name))


def download_report_text(base_url, report_id, token, xmeter_ip):
    """ Download performance test comparison report """
    global REPORT_ID
    if str(report_id) != REPORT_ID:
        HTTP_HEADER["host"] = xmeter_ip
        HTTP_HEADER["xmeter-authorization"] = token
        test_results_url = "{}/rest/api/asteroid/report/testrun/{}/withprev".format(base_url, report_id)
        try:
            response = requests.post(test_results_url, headers=HTTP_HEADER, verify=False)
            compare_result_file_url = response.json()["url"]
            logger.info("compare_result_file: {}".format(compare_result_file_url))

            download_results = [compare_result_file_url]
            comparison_results = "./data/ComparisonResults"
            if not os.path.exists(comparison_results):
                os.makedirs(comparison_results)
            download_test_results(download_results, comparison_results)
            REPORT_ID = str(report_id)
        except Exception as ec:
            logger.error("Failed to download performance test comparison report: {}".format(ec))
    else:
        logger.info("The test report has been downloaded")
        pass


def get_localstorage(driver, param):
    js_get_param_value = "return localStorage.getItem('{}')".format(param)
    param_value = driver.execute_script(js_get_param_value)
    logger.info("localStorage['{}']: {}".format(param, param_value))
    return param_value


def save_emqx_cluster_screenshot(emqx_nodes: list, grafana_monitors: list, driver, start_time, end_time, report_name):
    """ Access the resource usage report of each node of emqx """
    grafana_address = grafana_monitors[0]
    for ip in emqx_nodes:
        node_consume_report_url = "{}?from={}&to={}&var-hosts={}&theme=light&orgId=1" \
            .format(grafana_address, start_time, end_time, ip)
        test_report_file_name = "{}_{}.png".format(report_name, ip)
        save_report_screenshot(page_url=node_consume_report_url, driver=driver,
                               screenshot_name=test_report_file_name, report_type=False)

        logger.info("emqx node {} resource usage URL: {}".format(ip, node_consume_report_url))
        pass


def extract_information(report_row):
    """ Process report.txt """
    report_name = re.split(' ', report_row, maxsplit=1)[0]
    report_url = re_http_path(report_row)
    xmeter_host = re_host(report_url)
    if xmeter_host is not None:
        report_id = re.split('/', report_url)[-1]
        logger.info("""
        Xmeter_ip: {}
        report_name: {}
        PerformanceTestReport_url: {}
        PerformanceTestReportID: {} """.format(xmeter_host, report_name, report_url, report_id))
        return xmeter_host, report_name, report_url, report_id
    else:
        logger.error("Failed to read test report information")
        raise


def main(report_log):
    report_line = str(report_log)
    xmeter_host, report_name, report_url, report_id = extract_information(report_line)
    start()
    driver = firefox_driver()
    try:
        """ login """
        login(driver=driver, ip=xmeter_host)

        """ Visit the Test Reports page """
        report_page_image = "{}_report.png".format(report_name)
        save_report_screenshot(page_url=report_url, driver=driver, screenshot_name=report_page_image, report_type=True)

        """ get token """
        token = get_localstorage(driver=driver, param="token")

        """ Get the resource usage report address of each node in the emq cluster """
        # Get the ip of each node of the emqx cluster
        emqx_nodes, grafana_monitors = node_grafana(xmeter_ip=xmeter_host, test_id=report_id, token=token)

        """ Get test report details """
        case_information = test_info(xmeter_ip=xmeter_host, test_id=report_id, token=token)
        start_time = case_information["start_time"]
        end_time = case_information["end_time"]
        asteroid_base_url = case_information["asteroid_base_url"]

        """ Access the resource usage report of each node of emqx """
        save_emqx_cluster_screenshot(emqx_nodes=emqx_nodes, grafana_monitors=grafana_monitors, driver=driver,
                                     start_time=start_time, end_time=end_time, report_name=report_name)

        """ Download performance test comparison report """
        download_report_text(base_url=asteroid_base_url, report_id=report_id, token=token, xmeter_ip=xmeter_host)
        driver.quit()
    except Exception as ec:
        driver.quit()
        logger.error("run failed: {}".format(ec))


if __name__ == '__main__':
    with open("./report.txt", "r") as rc:
        for params in rc.readlines():
            logger.info(params)
            main(report_log=params)
    # for line in open("./report.txt", "r"):
    #     logger.info(line)
    #     demo(report_log=line)
