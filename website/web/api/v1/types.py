#! /usr/bin/env python
from typing import Any
from typing import List

from typing_extensions import TypedDict


class MetaDataType(TypedDict):
    """Defines a type for a question with user answers"""

    count: int
    offset: int
    limit: int


class ResultType(TypedDict):
    """Defines a type for a question with user answers"""

    data: List[Any]
    metadata: MetaDataType
