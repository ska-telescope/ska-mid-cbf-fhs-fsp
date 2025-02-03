# -*- coding: utf-8 -*-
#
# This file is part of the SKA Mid CBF FHS FSP project With inspiration gathered from the Mid.CBF MCS project
#
# Distributed under the terms of the BSD 3-clause new license.
# See LICENSE.txt for more info.


from __future__ import annotations

from ska_mid_cbf_fhs_common import FhsLowLevelDeviceBase
from tango.server import attribute, device_property

from ska_mid_cbf_fhs_fsp.dev_b.dev_b_component_manager import DevBComponentManager


class DevB(FhsLowLevelDeviceBase):
    DevBType = device_property(dtype="str")

    @attribute(dtype=int, abs_change=1)
    def bAttr1(self) -> int:
        return self.component_manager.b_attr_1

    @bAttr1.write
    def bAttr1(self, value: int) -> None:
        self.component_manager.b_attr_1 = value
    
    @attribute(dtype=str)
    def bAttr2(self) -> str:
        return self.component_manager.b_attr_2

    @bAttr2.write
    def bAttr2(self, value: str) -> None:
        self.component_manager.b_attr_2 = value
    
    @attribute(dtype=str)
    def bAttr3(self) -> str:
        return self.component_manager.b_attr_3

    @bAttr3.write
    def bAttr3(self, value: str) -> None:
        self.component_manager.b_attr_3 = value

    def create_component_manager(self: DevB) -> DevBComponentManager:
        return DevBComponentManager(
            device=self,
            attr_change_callback=self.push_change_event,
            attr_archive_callback=self.push_archive_event,
            health_state_callback=self._update_health_state,
            communication_state_callback=self._communication_state_changed,
            obs_command_running_callback=self._obs_command_running,
            component_state_callback=self._component_state_changed,
            obs_state_action_callback=self._obs_state_action,
            logger=self.logger,
        )

    def always_executed_hook(self: DevB) -> None:
        """Hook to be executed before any commands."""

    def delete_device(self: DevB) -> None:
        """Hook to delete device."""

    def init_command_objects(self: DevB) -> None:
        # init the LRC
        commandsAndMethods = [
            ("Start", "start"),
            ("Stop", "stop"),
            ("TestCmd", "test_cmd"),
        ]
        super().init_command_objects(commandsAndMethods)

        # init the fast commands
        commandsAndClasses = [
            ("Recover", FhsLowLevelDeviceBase.RecoverCommand),
            ("Configure", FhsLowLevelDeviceBase.ConfigureCommand),
            ("Deconfigure", FhsLowLevelDeviceBase.DeconfigureCommand),
            ("GetStatus", FhsLowLevelDeviceBase.GetStatusCommand),
            ("GoToIdle", FhsLowLevelDeviceBase.GoToIdleCommand),
        ]

        super().init_fast_command_objects(commandsAndClasses)


def main(args=None, **kwargs):
    return DevB.run_server(args=args or None, **kwargs)


if __name__ == "__main__":
    main()
