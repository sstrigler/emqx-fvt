# -*- encoding: utf-8 -*-
"""
@File    : screenshot.py
@Time    : 2022/3/3 10:42 上午
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

root_path = os.path.dirname(os.path.dirname(__file__))
project_path = "./"
image_file_path = "./data/image"
if not os.path.exists(image_file_path):
    os.makedirs(image_file_path)

logger = logging.getLogger(__name__)
formatter = logging.Formatter('[%(asctime)s] - %(filename)s] - %(levelname)s: %(message)s')
level = logging.DEBUG
logger.setLevel(level=level)
console = logging.StreamHandler()
console.setLevel(level=level)
console.setFormatter(formatter)
logger.addHandler(console)

log_path = "./data/log"
if not os.path.exists(log_path):
    os.makedirs(log_path)
log_filename = os.path.join(log_path, '{}.log'.format(time.strftime("%Y%m%d_%H%M%S")))
console_file = logging.FileHandler(log_filename, encoding='utf-8')
console_file.setLevel(level=level)
console_file.setFormatter(formatter)
logger.addHandler(console_file)


logger.info(root_path)
logger.info(project_path)
logger.info(image_file_path)
logger.info(log_path)


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
        .until(lambda diver: driver.find_element_by_css_selector("[name=form-alias]")).send_keys('xfypp@sina.com')
    driver.find_element_by_css_selector("[type=password]").send_keys('xfypp@sina.com')
    driver.find_element_by_css_selector("#submitLogin").click()
    time.sleep(3)


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


def demo(report_log):
    driver = firefox_driver()
    report_url = str(report_log)

    """ report_url process"""
    report_name = re.split(' ', report_url, maxsplit=1)[0]
    re_http = r'(ht|f)tp(s?)\:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(\/?)([a-zA-Z0-9\-\.\?\,\'\/\\\+&%\$#_]*)?'
    report_url = re.search(re_http, report_url, re.M | re.I).group()
    re_ip = r"((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))"
    re_report_ip = re.search(re_ip, report_url)
    if re_report_ip is not None:
        report_ip = re_report_ip.group()
        report_id = re.split('/', report_url)[-1]

        logger.info("report_name: {}".format(report_name))
        logger.info("PerformanceTestReport_url: {}".format(report_url))
        logger.info("Xmeter_ip: {}".format(report_ip))
        logger.info("PerformanceTestReportID: {}".format(report_id))

        """ login """
        login(driver=driver, ip=report_ip)

        """ get cookies """
        cookies = driver.get_cookies()
        js_get_account_id = "return localStorage.getItem('accountId')"
        account_id = driver.execute_script(js_get_account_id)
        js_get_token = "return localStorage.getItem('token')"
        token = driver.execute_script(js_get_token)

        logger.info("Browser Cookies: {}".format(cookies))
        logger.info("localStorage['accountID']: {}".format(account_id))
        logger.info("localStorage['token']: {}".format(token))

        """ Get test report details """
        header = {
            'Connection': 'keep-alive',
            'Accept-Language': 'en-US',
            'host': '13.251.133.132',
            'ontent-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'xmeter-authorization': token,
            'Referer': 'https://13.251.133.132/commercialPage.html'
        }
        run_test_info_url = "https://{}/commercial_service/rest/testcase/testrun/{}/{}" \
            .format(report_ip, account_id, report_id)

        try:
            response = requests.get(run_test_info_url, headers=header, verify=False)
            response_body = dict(response.json())

            # Get test start time、test end time、EmqxClusterNode
            start_time = int(response_body.get("startTimeAsLong"))
            end_time = int(response_body['endTimeAsLong']) + 20000
            grafana_report_addr = response_body['reports'][0]['reportAddr']
            conf_other_para = json.loads(response_body['confOtherPara'])

            # Get the ip of each node of the emqx cluster
            cluster_node = []
            for i in conf_other_para['variables']:
                node = i['value']
                cluster_node.append(node)

            logger.info("test start time: %d" % start_time)
            logger.info("test end time: %d" % end_time)
            logger.info("emqx cluster node ip: {}".format(cluster_node))

            """ Visit the Test Reports page """
            grafana_report_url = "{}?from={}&to={}&var-testId={}&theme=light&orgId=1" \
                .format(grafana_report_addr, start_time, end_time, report_id)
            driver.get(grafana_report_url)

            logger.info("Grafana test report page_url: {}".format(grafana_report_url))

            WebDriverWait(driver=driver, timeout=60, poll_frequency=0.5) \
                .until(lambda diver: driver.find_elements_by_css_selector("[class='graph-legend-alias pointer']"))
            time.sleep(3)
            scroll(driver=driver, report_type=True)

            """ Get a screenshot of the test report page """
            test_report_file_name = "{}_report.png".format(report_name)

            logger.info("Test report screenshot file name: {}".format(test_report_file_name))

            driver.save_screenshot(os.path.join(image_file_path, test_report_file_name))

            """ Get the resource usage report address of each node in the emq cluster """
            emqx_grafana_cluster_node_api = "https://{}/commercial_service/rest/applications/testrun/{}/monitors" \
                .format(report_ip, report_id)
            logger.info("Get emqx resource usage page address api: {}".format(emqx_grafana_cluster_node_api))
            emqx_grafana_cluster_addr = requests.get(emqx_grafana_cluster_node_api, headers=header, verify=False)
            emqx_grafana_addr = dict(emqx_grafana_cluster_addr.json())[cluster_node[0]]
            logger.info("emqx resource usage page address: {}".format(emqx_grafana_addr))

            """ Access the resource usage report of each node of emqx """
            for ip in cluster_node:
                node_consume_report_url = "{}?from={}&to={}&var-hosts={}&theme=light&orgId=1" \
                    .format(emqx_grafana_addr, start_time, end_time, ip)
                driver.get(node_consume_report_url)

                logger.info("emqx node {} resource usage URL: {}".format(ip, node_consume_report_url))

                WebDriverWait(driver=driver, timeout=60, poll_frequency=0.5) \
                    .until(lambda diver: driver.find_elements_by_css_selector("[class='graph-legend-alias pointer']"))
                time.sleep(3)
                scroll(driver=driver, report_type=False)

                """ Get a screenshot of the test report page """
                test_report_file_name = "{}_{}.png".format(report_name, ip)

                logger.info("Test report screenshot file name: {}".format(test_report_file_name))

                driver.save_screenshot(os.path.join(image_file_path, test_report_file_name))

        except Exception as ec:
            logger.error(ec)
            driver.quit()
    else:
        driver.quit()


if __name__ == '__main__':
    with open("./report.txt", "r") as rc:
        for params in rc.readlines():
            logger.info(params)
            demo(report_log=params)
    # for line in open("./report.txt", "r"):
    #     logger.info(line)
    #     demo(report_log=line)
