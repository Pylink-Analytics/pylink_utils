from dataclasses import dataclass
from typing import Literal, Optional, List, Union

import bs4.element
from bs4 import BeautifulSoup
from bs4.element import NavigableString
from lxml import etree


@dataclass
class HTML2DictMetaData:
    html: str
    method: Literal["element", "xpath"]
    element_type: Optional[str] = None
    element_class_type: Optional[str] = None
    element_class: Optional[str] = None
    xpath: Optional[str] = None
    edge_cases_keep_text: List[str] = None

    def __post_init__(self):
        if self.method == "element":
            if self.element_type is None or self.element_class is None:
                raise NameError(
                    "When selecting 'element' method, the element_type and element_class inputs must be provided."
                )
        elif self.method == "xpath":
            if self.xpath is None:
                raise NameError("When selecting the 'xpath' method, the xpath input must be given.")


class HTML2Dict:
    def __init__(self):
        self.create_dictionary_map = {"element": self._create_dictionary_bs4, "xpath": self._create_dictionary_etree}

        self.soup = None
        self.task = None

    def convert_html_to_dict(self, task: HTML2DictMetaData):

        self.task = task
        self.soup = BeautifulSoup(task.html, "lxml")
        if self.task.edge_cases_keep_text is None:
            self.task.edge_cases_keep_text = []

        if self.task.method == "element":
            search_result_blocks = self.soup.find_all(self.task.element_type, {self.task.element_class_type: task.element_class})
        elif self.task.method == "xpath":
            dom = etree.HTML(str(self.soup))
            dom = etree.ElementTree(dom)
            search_result_blocks = dom.findall(self.task.xpath)

        return self._handle_responses(search_result_blocks=search_result_blocks)

    def _handle_responses(
        self, search_result_blocks: List[Union[bs4.element.Tag, etree._Element]]
    ) -> List[Union[dict, str]]:
        responses = []
        if search_result_blocks is None:
            if self.task.method.lower() == "element":
                error_msg = (
                    f"The given inputs corresponding to \"BeautifulSoup.find_all('{self.task.element_type}', "
                    f"{{'class', '{self.task.element_class}'}})\" returned no results."
                )
            else:
                error_msg = f"No elements with the given xpath - {self.task.xpath} - were found in the DOM"
            return [error_msg]
        for block in search_result_blocks:
            results_dict = self.create_dictionary_map[self.task.method](block)
            results_dict = self._clean_single_item_lists_from_dict(results_dict)
            responses.append(results_dict)

        return responses

    def _create_dictionary_bs4(self, block: bs4.element.Tag, class_: str = None) -> dict:
        block_dictionary = {}
        unnammed_class_count = 0
        nav_str_count = 0
        for element in block.children:
            if isinstance(element, NavigableString):
                if class_ in self.task.edge_cases_keep_text:
                    key = f"{class_}_text_{nav_str_count}"
                    value = element.text
                    value = value.strip()
                    if value:
                        block_dictionary[key] = value
                        nav_str_count += 1

                continue
            if element.has_attr("class"):
                if not element["class"]:
                    element["class"].append(f"unnamed_class_{unnammed_class_count}")
                    unnammed_class_count += 1
                key = element["class"][0]
                key = key.replace("-", "_")

                # element.children is an iterator object so has no len property that can be checked
                i = 0
                for i, _ in enumerate(element.children):
                    pass

                if i == 0:
                    if (value := element.text) is None:
                        value = ""
                    value = value.strip()
                    block_dictionary[key] = value
                else:
                    value = self._create_dictionary_bs4(element, class_=key)
                    if key in block_dictionary:
                        block_dictionary[key].append(value)
                    else:
                        block_dictionary[key] = [value]

        return block_dictionary

    def _create_dictionary_etree(self, block: etree._Element) -> dict:
        block_dictionary = {}
        for element in block.iterchildren():
            if "class" in element.attrib:
                key = element.attrib["class"].split(" ")[0]
                key = key.replace("-", "_")

                # element.iterchildren() is an iterator object so has no len property that can be checked
                i = 0
                for i, _ in enumerate(element.iterchildren()):
                    pass

                if i == 0:
                    if (value := element.text) is None:
                        value = ""
                    value = value.strip()
                    block_dictionary[key] = value
                else:
                    value = self._create_dictionary_etree(element)
                    if key in block_dictionary:
                        block_dictionary[key].append(value)
                    else:
                        block_dictionary[key] = [value]
        return block_dictionary

    def _clean_single_item_lists_from_dict(self, dict_to_clean: dict) -> dict:
        for key, value in dict_to_clean.items():
            if isinstance(value, list):
                if len(value) == 1:
                    if isinstance((return_value := value[0]), dict):
                        return_value = self._clean_single_item_lists_from_dict(return_value)
                    dict_to_clean[key] = return_value
                else:
                    return_value = []
                    for item in value:
                        if isinstance(item, dict):
                            return_value.append(self._clean_single_item_lists_from_dict(item))
                    dict_to_clean[key] = return_value

        return dict_to_clean
