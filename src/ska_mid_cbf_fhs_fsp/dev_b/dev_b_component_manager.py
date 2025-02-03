from __future__ import annotations  # allow forward references in type hints

from dataclasses import dataclass
from typing import Any

import numpy as np
from dataclasses_json import dataclass_json
from ska_control_model import CommunicationStatus, ResultCode
from ska_mid_cbf_fhs_common import FhsLowLevelComponentManagerBase

from ska_mid_cbf_fhs_fsp.dev_b.dev_b_simulator import DevBSimulator


@dataclass_json
@dataclass
class DevBConfig:
    something: str = "abcd"


##
# status class that will be populated by the APIs and returned to provide the status
##
@dataclass_json
@dataclass
class DevBStatus:
    b_value: str = "wxyz"


class DevBComponentManager(FhsLowLevelComponentManagerBase):
    def __init__(
        self: DevBComponentManager,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            *args,
            simulator_api=DevBSimulator,
            **kwargs,
        )

        self.b_attr_1 = 1234
        self.b_attr_2 = "B2_DEFAULT"
        self.b_attr_3 = "B3_DEFAULT"

    def go_to_idle(self: DevBComponentManager) -> tuple[ResultCode, str]:
        result = self.deconfigure(DevBConfig().to_dict())

        if result[0] is not ResultCode.FAILED:
            result = super().go_to_idle()
        else:
            self.logger.error("Unable to go to idle, result from deconfiguring was FAILED")

        return result

    # --------------------
    # Public Commands
    # --------------------
    # TODO Determine what needs to be communicated with here
    def start_communicating(self: DevBComponentManager) -> None:
        """Establish communication with the component, then start monitoring."""
        if self._communication_state == CommunicationStatus.ESTABLISHED:
            self.logger.info("Already communicating.")
            return

        super().start_communicating()
