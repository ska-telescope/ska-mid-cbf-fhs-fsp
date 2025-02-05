from __future__ import annotations

import functools
import json
import logging
from threading import Event
from typing import Any, Callable, Optional

import jsonschema
import tango
from ska_control_model import CommunicationStatus, HealthState, ObsState, ResultCode, SimulationMode, TaskStatus
from ska_control_model.faults import StateModelError
from ska_mid_cbf_fhs_common import FhsBaseDevice, FhsComponentManagerBase, FhsHealthMonitor, FhsObsStateMachine
from ska_tango_base.base.base_component_manager import TaskCallbackType
from tango import DeviceProxy, EventData, EventType

from ska_mid_cbf_fhs_fsp.fsp_all_modes.fsp_all_modes_helpers import FSPMode

from .fsp_all_modes_config import config_schema


class FSPAllModesComponentManager(FhsComponentManagerBase):
    def __init__(
        self: FSPAllModesComponentManager,
        *args: Any,
        device: FhsBaseDevice,
        logger: logging.Logger,
        simulation_mode: SimulationMode = SimulationMode.FALSE,
        attr_change_callback: Callable[[str, Any], None] | None = None,
        attr_archive_callback: Callable[[str, Any], None] | None = None,
        health_state_callback: Callable[[HealthState], None] | None = None,
        obs_command_running_callback: Callable[[str, bool], None],
        emulation_mode: bool = False,
        **kwargs: Any,
    ) -> None:
        self.device = device
        self._fsp_id = device.device_id
        self._fsp_mode = FSPMode.UNKNOWN

        # TODO: move this config into JSON file
        self.attr_subscriptions = {
            FSPMode.CORR: {
                device.dev_a_fqdn: ["aAttr"],
                device.dev_b_fqdn: ["bAttr1", "bAttr2"],
            },
            FSPMode.PST: {
                device.dev_b_fqdn: ["bAttr2", "bAttr3"],
                device.dev_c_fqdn: ["cAttr"],
            },
            FSPMode.PSS: {
                device.dev_a_fqdn: ["aAttr"],
                device.dev_b_fqdn: ["bAttr1", "bAttr3"],
                device.dev_c_fqdn: ["cAttr"],
            },
        }
        self._config_id = ""

        self.simulation_mode = simulation_mode
        self.emulation_mode = emulation_mode

        self._proxies: dict[str, DeviceProxy] = {}

        self._proxies[device.dev_a_fqdn] = None
        self._proxies[device.dev_b_fqdn] = None
        self._proxies[device.dev_c_fqdn] = None

        # store the subscription event_ids here with a key (fqdn for deviceproxies)
        self.subscription_event_ids: dict[str, set[int]] = {}

        self.fhs_health_monitor = FhsHealthMonitor(
            logger=logger,
            get_device_health_state=self.get_device_health_state,
            update_health_state_callback=health_state_callback,
        )

        super().__init__(
            *args,
            logger=logger,
            attr_change_callback=attr_change_callback,
            attr_archive_callback=attr_archive_callback,
            health_state_callback=health_state_callback,
            obs_command_running_callback=obs_command_running_callback,
            max_queue_size=32,
            simulation_mode=simulation_mode,
            emulation_mode=emulation_mode,
            **kwargs,
        )

        self.fsp_mode = FSPMode.CORR

    @property
    def fsp_mode(self) -> FSPMode:
        return self._fsp_mode

    @fsp_mode.setter
    def fsp_mode(self, new_mode: FSPMode):
        self._apply_fsp_mode_subscriptions(new_mode)

        self._fsp_mode = new_mode

        self.logger.info(f"FSP Mode Changed to: {new_mode.name}")

    @property
    def attr_subscriptions(self):
        try:
            return self._attr_subscriptions
        except Exception:
            return None

    @attr_subscriptions.setter
    def attr_subscriptions(self, attr_map: dict[int, dict[str, list[str]]]):
        self._attr_subscriptions = {
            mode: {fqdn: {"attrs": set(attrs), "event_ids": {attr: -1 for attr in attrs}} for fqdn, attrs in fqdns.items()}
            for mode, fqdns in attr_map.items()
        }

    def attr_change_callback(self, event: EventData):
        self.logger.debug(
            f"FSP Attribute Change: DEVICE={event.device.dev_name()}, ATTR={event.attr_name}, VALUE={event.attr_value.value if event.attr_value is not None else 'None'}"
        )

    def start_communicating(self: FSPAllModesComponentManager) -> None:
        """Establish communication with the component, then start monitoring."""
        try:
            if not self.simulation_mode:
                if self._communication_state == CommunicationStatus.ESTABLISHED:
                    self.logger.info("Already communicating.")
                    return

                self.logger.info("Establishing Communication with low-level proxies")

                for fqdn, dp in self._proxies.items():
                    if dp is None:
                        self.logger.info(f"Establishing Communication with {fqdn}")
                        dp = DeviceProxy(device_name=fqdn)
                        # NOTE: this crashes when adminMode is memorized because it gets called before the devices are ready
                        self._subscribe_to_change_event(dp, "healthState", fqdn, self.proxies_health_state_change_event)
                        self._subscribe_to_change_event(dp, "longRunningCommandResult", fqdn, self._long_running_command_callback)
                        self._proxies[fqdn] = dp
                print(f"HEALTH_STATE REGISTERED EVENTS: {self.subscription_event_ids}")
                self._apply_fsp_mode_subscriptions(self.fsp_mode)
                super().start_communicating()
        except tango.DevFailed as ex:
            self.logger.error(f"Failed connecting to FHS Low-level devices; {ex}")
            self._update_communication_state(communication_state=CommunicationStatus.NOT_ESTABLISHED)
            return

    def stop_communicating(self: FSPAllModesComponentManager) -> None:
        """Close communication with the component, then stop monitoring."""
        try:
            for fqdn in self._proxies:
                # unsubscribe from any attribute change events
                self._unsubscribe_from_events(fqdn)
                self._proxies[fqdn] = None

            # Event unsubscription will also be placed here
            super().stop_communicating()
        except tango.DevFailed as ex:
            self.logger.error(f"Failed close device proxies to FHS Low-level devices; {ex}")

    def is_go_to_idle_allowed(self: FSPAllModesComponentManager) -> bool:
        self.logger.debug("Checking if gotoidle is allowed...")
        errorMsg = f"go_to_idle not allowed in ObsState {self.obs_state}; " "must be in ObsState.READY"

        return self.is_allowed(errorMsg, [ObsState.READY])

    def is_obs_reset_allowed(self: FSPAllModesComponentManager) -> bool:
        self.logger.debug("Checking if ObsReset is allowed...")
        errorMsg = f"ObsReset not allowed in ObsState {self.obs_state}; \
            must be in ObsState.FAULT or ObsState.ABORTED"

        return self.is_allowed(errorMsg, [ObsState.FAULT, ObsState.ABORTED])

    def configure_scan(
        self: FSPAllModesComponentManager,
        argin: str,
        task_callback: Optional[Callable] = None,
    ) -> tuple[TaskStatus, str]:
        return self.submit_task(
            func=self._configure_scan,
            args=[argin],
            task_callback=task_callback,
        )

    def go_to_idle(
        self: FSPAllModesComponentManager,
        task_callback: Optional[Callable] = None,
    ) -> tuple[TaskStatus, str]:
        return self.submit_task(
            func=functools.partial(
                self._obs_command_with_callback,
                hook="deconfigure",
                command_thread=self._go_to_idle,
            ),
            task_callback=task_callback,
            is_cmd_allowed=self.is_go_to_idle_allowed,
        )

    def obs_reset(
        self: FSPAllModesComponentManager,
        task_callback: Optional[Callable] = None,
    ) -> tuple[TaskStatus, str]:
        return self.submit_task(
            func=functools.partial(
                self._obs_command_with_callback,
                hook="obsreset",
                command_thread=functools.partial(
                    self._obs_reset,
                    from_state=self.obs_state,
                ),
            ),
            task_callback=task_callback,
            is_cmd_allowed=self.is_obs_reset_allowed,
        )

    def scan(self: FSPAllModesComponentManager, argin: str, task_callback: Optional[Callable] = None) -> tuple[TaskStatus, str]:
        return self.submit_task(
            func=functools.partial(
                self._obs_command_with_callback,
                hook="start",
                command_thread=self._scan,
            ),
            args=[argin],
            task_callback=task_callback,
        )

    def end_scan(
        self: FSPAllModesComponentManager,
        task_callback: Optional[Callable] = None,
    ) -> tuple[TaskStatus, str]:
        return self.submit_task(
            func=functools.partial(
                self._obs_command_with_callback,
                hook="stop",
                command_thread=self._end_scan,
            ),
            task_callback=task_callback,
        )

    def abort_commands(
        self: FSPAllModesComponentManager,
        task_callback: TaskCallbackType | None = None,
    ) -> tuple[TaskStatus, str]:
        """
        Stop all devices.

        :return: None
        """
        self._obs_state_action_callback(FhsObsStateMachine.ABORT_INVOKED)
        result = super().abort_commands(task_callback)

        result = self._stop_proxies()

        self._obs_state_action_callback(FhsObsStateMachine.ABORT_COMPLETED)
        return result

    def _apply_fsp_mode_subscriptions(self, mode: FSPMode):
        EMPTY_SET = {"attrs": set(), "event_ids": {}}
        for fqdn in self._proxies:
            if self._proxies[fqdn] is not None:
                new_subs = self.attr_subscriptions[mode].get(fqdn, EMPTY_SET)
                if self.fsp_mode == -1 or self.fsp_mode == mode:
                    for sub_attr in filter(lambda a: new_subs["event_ids"][a] == -1, new_subs["attrs"]):
                        self.logger.debug(f"Applying subscription for attribute {sub_attr} for fqdn {fqdn} for mode {mode.name}")
                        new_subs["event_ids"][sub_attr] = self._proxies[fqdn].subscribe_event(
                            sub_attr, EventType.CHANGE_EVENT, self.attr_change_callback
                        )
                else:
                    curr_subs = self.attr_subscriptions[self._fsp_mode].get(fqdn, EMPTY_SET)
                    for unsub_attr in curr_subs["attrs"] - new_subs["attrs"]:
                        self.logger.debug(
                            f"REMOVING subscription for attribute {unsub_attr} for fqdn {fqdn} for mode {mode.name}"
                        )
                        if (event_id := curr_subs["event_ids"][unsub_attr]) != -1:
                            self._proxies[fqdn].unsubscribe_event(event_id)
                            curr_subs["event_ids"][unsub_attr] = -1
                    for sub_attr in new_subs["attrs"] - curr_subs["attrs"]:
                        self.logger.debug(f"Applying subscription for attribute {sub_attr} for fqdn {fqdn} for mode {mode.name}")
                        new_subs["event_ids"][sub_attr] = self._proxies[fqdn].subscribe_event(
                            sub_attr, EventType.CHANGE_EVENT, self.attr_change_callback
                        )
            else:
                self.logger.debug(f"Skipping applying subscriptions for FQDN {fqdn} as is has not yet been connected to.")

    def _configure_scan(
        self: FSPAllModesComponentManager,
        argin: str,
        task_callback: Optional[Callable] = None,
        task_abort_event: Optional[Event] = None,
    ) -> None:
        """Read from JSON Config argin and setup the FSP controller with initial configuration from the control software"""
        try:
            self._obs_state_action_callback(FhsObsStateMachine.CONFIGURE_INVOKED)
            task_callback(status=TaskStatus.IN_PROGRESS)
            configuration = json.loads(argin)
            jsonschema.validate(configuration, config_schema)
            if self.task_abort_event_is_set("ConfigureScan", task_callback, task_abort_event):
                return

            self._config_id = configuration["config_id"]

            if not self.simulation_mode:
                match self.fsp_mode:
                    case FSPMode.CORR:
                        # Dev A Configuration
                        self.logger.info("Dev A Configuring..")
                        result = self._proxies[self.device.dev_a_fqdn].Configure(json.dumps({"something": "a_config"}))
                        if result[0] == ResultCode.FAILED:
                            self.logger.error(f"Configuration of Dev A failed: {result[1]}")
                            self._reset_devices([self.device.dev_a_fqdn])
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.REJECTED,
                                "Configuration of low-level fhs device failed",
                            )
                            return
                    case FSPMode.PST:
                        # Dev B Configuration
                        self.logger.info("Dev B Configuring..")
                        result = self._proxies[self.device.dev_b_fqdn].Configure(json.dumps({"something": "b_config"}))
                        if result[0] == ResultCode.FAILED:
                            self.logger.error(f"Configuration of Dev B failed: {result[1]}")
                            self._reset_devices([self.device.dev_b_fqdn])
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.REJECTED,
                                "Configuration of low-level fhs device failed",
                            )
                            return
                    case FSPMode.PSS:
                        # Dev C Configuration
                        self.logger.info("Dev C Configuring..")
                        result = self._proxies[self.device.dev_c_fqdn].Configure(json.dumps({"something": "c_config"}))
                        if result[0] == ResultCode.FAILED:
                            self.logger.error(f"Configuration of Dev C failed: {result[1]}")
                            self._reset_devices([self.device.dev_c_fqdn])
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.REJECTED,
                                "Configuration of low-level fhs device failed",
                            )
                            return
                    case _:
                        pass

            self._set_task_callback(task_callback, TaskStatus.COMPLETED, ResultCode.OK, "ConfigureScan completed OK")
            self._obs_state_action_callback(FhsObsStateMachine.CONFIGURE_COMPLETED)
            return
        except StateModelError as ex:
            self.logger.error(f"Attempted to call command from an incorrect state: {repr(ex)}")
            self._set_task_callback(
                task_callback,
                TaskStatus.COMPLETED,
                ResultCode.REJECTED,
                "Attempted to call ConfigureScan command from an incorrect state",
            )
        except jsonschema.ValidationError as ex:
            self.logger.error(f"Invalid json provided for ConfigureScan: {repr(ex)}")
            self._obs_state_action_callback(FhsObsStateMachine.GO_TO_IDLE)
            self._set_task_callback(
                task_callback, TaskStatus.COMPLETED, ResultCode.REJECTED, "Arg provided does not match schema for ConfigureScan"
            )
        except Exception as ex:
            self.logger.error(repr(ex))
            self._update_communication_state(communication_state=CommunicationStatus.NOT_ESTABLISHED)
            self._obs_state_action_callback(FhsObsStateMachine.GO_TO_IDLE)
            self._set_task_callback(
                task_callback, TaskStatus.COMPLETED, ResultCode.FAILED, "Failed to establish proxies to HPS FSP devices"
            )

    def _scan(
        self: FSPAllModesComponentManager,
        argin: int,
        task_callback: Optional[Callable] = None,
        task_abort_event: Optional[Event] = None,
    ) -> None:
        """
        Begin scan operation.

        :param argin: scan ID integer

        :return: None
        """
        try:
            # set task status in progress, check for abort event
            self._scan_id = argin

            if not self.simulation_mode:
                match self.fsp_mode:
                    case FSPMode.CORR:
                        try:
                            self._proxies[self.device.dev_a_fqdn].Start()
                        except tango.DevFailed as ex:
                            self.logger.error(repr(ex))
                            self._update_communication_state(communication_state=CommunicationStatus.NOT_ESTABLISHED)
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.FAILED,
                                "Failed to establish proxies to FHS FSP devices",
                            )
                            return
                    case FSPMode.PST:
                        try:
                            self._proxies[self.device.dev_b_fqdn].Start()
                        except tango.DevFailed as ex:
                            self.logger.error(repr(ex))
                            self._update_communication_state(communication_state=CommunicationStatus.NOT_ESTABLISHED)
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.FAILED,
                                "Failed to establish proxies to FHS FSP devices",
                            )
                            return
                    case FSPMode.PSS:
                        try:
                            self._proxies[self.device.dev_c_fqdn].Start()
                        except tango.DevFailed as ex:
                            self.logger.error(repr(ex))
                            self._update_communication_state(communication_state=CommunicationStatus.NOT_ESTABLISHED)
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.FAILED,
                                "Failed to establish proxies to FHS FSP devices",
                            )
                            return
                    case _:
                        pass

            # Update obsState callback
            self._set_task_callback(task_callback, TaskStatus.COMPLETED, ResultCode.OK, "Scan completed OK")
            return
        except StateModelError as ex:
            self.logger.error(f"Attempted to call command from an incorrect state: {repr(ex)}")
            self._set_task_callback(
                task_callback,
                TaskStatus.COMPLETED,
                ResultCode.REJECTED,
                "Attempted to call Scan command from an incorrect state",
            )

    def _end_scan(
        self: FSPAllModesComponentManager,
        task_callback: Optional[Callable] = None,
        task_abort_event: Optional[Event] = None,
    ) -> None:
        """
        End scan operation.

        :return: None
        """
        try:
            task_callback(status=TaskStatus.IN_PROGRESS)
            if self.task_abort_event_is_set("EndScan", task_callback, task_abort_event):
                return

            if not self.simulation_mode:
                match self.fsp_mode:
                    case FSPMode.CORR:
                        try:
                            self._proxies[self.device.dev_a_fqdn].Stop()
                        except tango.DevFailed as ex:
                            self.logger.error(repr(ex))
                            self._update_communication_state(communication_state=CommunicationStatus.NOT_ESTABLISHED)
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.FAILED,
                                "Failed to establish proxies to FHS FSP devices",
                            )
                            return
                    case FSPMode.PST:
                        try:
                            self._proxies[self.device.dev_b_fqdn].Stop()
                        except tango.DevFailed as ex:
                            self.logger.error(repr(ex))
                            self._update_communication_state(communication_state=CommunicationStatus.NOT_ESTABLISHED)
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.FAILED,
                                "Failed to establish proxies to FHS FSP devices",
                            )
                            return
                    case FSPMode.PSS:
                        try:
                            self._proxies[self.device.dev_c_fqdn].Stop()
                        except tango.DevFailed as ex:
                            self.logger.error(repr(ex))
                            self._update_communication_state(communication_state=CommunicationStatus.NOT_ESTABLISHED)
                            self._set_task_callback(
                                task_callback,
                                TaskStatus.COMPLETED,
                                ResultCode.FAILED,
                                "Failed to establish proxies to FHS FSP devices",
                            )
                            return
                    case _:
                        pass

            # Update obsState callback
            self._set_task_callback(task_callback, TaskStatus.COMPLETED, ResultCode.OK, "EndScan completed OK")
            return
        except StateModelError as ex:
            self.logger.error(f"Attempted to call command from an incorrect state: {repr(ex)}")
            self._set_task_callback(
                task_callback,
                TaskStatus.COMPLETED,
                ResultCode.REJECTED,
                "Attempted to call EndScan command from an incorrect state",
            )

    # A replacement for unconfigure
    def _go_to_idle(
        self: FSPAllModesComponentManager,
        task_callback: Optional[Callable] = None,
        task_abort_event: Optional[Event] = None,
    ) -> None:
        try:
            task_callback(status=TaskStatus.IN_PROGRESS)
            if self.task_abort_event_is_set("GoToIdle", task_callback, task_abort_event):
                return

            # Reset all device proxies
            self._reset_devices(self._proxies.keys())

            self._set_task_callback(task_callback, TaskStatus.COMPLETED, ResultCode.OK, "GoToIdle completed OK")
            return
        except StateModelError as ex:
            self.logger.error(f"Attempted to call command from an incorrect state: {repr(ex)}")
            self._set_task_callback(
                task_callback,
                TaskStatus.COMPLETED,
                ResultCode.REJECTED,
                "Attempted to call GoToIdle command from an incorrect state",
            )
        except Exception as ex:
            self.logger.error(f"ERROR SETTING GO_TO_IDLE: {repr(ex)}")

    def _obs_reset(
        self: FSPAllModesComponentManager,
        task_callback: Optional[Callable] = None,
        task_abort_event: Optional[Event] = None,
        from_state=ObsState.ABORTED,
    ) -> None:
        try:
            task_callback(status=TaskStatus.IN_PROGRESS)
            if self.task_abort_event_is_set("ObsReset", task_callback, task_abort_event):
                return

            # If in FAULT state, devices may still be running, so make sure they are stopped
            if from_state is ObsState.FAULT:
                self._stop_proxies()

            # Reset all device proxies
            self._reset_devices(self._proxies.keys())

            self._set_task_callback(task_callback, TaskStatus.COMPLETED, ResultCode.OK, "ObsReset completed OK")
            return
        except StateModelError as ex:
            self.logger.error(f"Attempted to call command from an incorrect state: {repr(ex)}")
            self._set_task_callback(
                task_callback,
                TaskStatus.COMPLETED,
                ResultCode.REJECTED,
                "Attempted to call ObsReset command from an incorrect state",
            )
        except Exception as ex:
            self.logger.error(f"Unexpected error in ObsReset command: {repr(ex)}")

    def _stop_proxies(self: FSPAllModesComponentManager):
        result = None
        for fqdn, proxy in self._proxies.items():
            if proxy is not None and fqdn in [
                self.device.dev_a_fqdn,
                self.device.dev_b_fqdn,
                self.device.dev_c_fqdn,
            ]:
                self.logger.info(f"Stopping proxy {fqdn}")
                result = proxy.Stop()
        return result

    def _reset_attributes(self: FSPAllModesComponentManager):
        self._config_id = ""

    def _reset_devices(self: FSPAllModesComponentManager, devices_name: list[str]):
        try:
            self._reset_attributes()
            for fqdn in devices_name:
                if self._proxies[fqdn] is not None:
                    self._log_go_to_idle_status(fqdn, self._proxies[fqdn].GoToIdle())
        except Exception as ex:
            self.logger.error(f"Error resetting specific devices : {repr(ex)}")

    def task_abort_event_is_set(
        self: FSPAllModesComponentManager,
        command_name: str,
        task_callback: Callable,
        task_abort_event: Event,
    ) -> bool:
        """
        Helper method for checking task abort event during command thread.

        :param command_name: name of command for result message
        :param task_callback: command tracker update_command_info callback
        :param task_abort_event: task executor abort event

        :return: True if abort event is set, otherwise False
        """
        if task_abort_event.is_set():
            task_callback(
                status=TaskStatus.ABORTED,
                result=(
                    ResultCode.ABORTED,
                    f"{command_name} command aborted by task executor abort event.",
                ),
            )
            return True
        return False

    def _log_go_to_idle_status(self: FSPAllModesComponentManager, ip_block_name: str, result: tuple[ResultCode, str]):
        if result[0] != ResultCode.OK:
            self.logger.error(f"FSP {self._fsp_id}: Unable to set to IDLE state for ipblock {ip_block_name}")
        else:
            self.logger.info(f"FSP {self._fsp_id}: {ip_block_name} set to IDLE")

    def _subscribe_to_change_event(
        self: FSPAllModesComponentManager,
        device_proxy,
        attribute: str,
        key: str,
        change_event_callback: Callable[[EventData], None],
    ):
        event_id = device_proxy.subscribe_event(attribute, EventType.CHANGE_EVENT, change_event_callback)
        if key in self.subscription_event_ids:
            self.subscription_event_ids[key].add(event_id)
        else:
            self.subscription_event_ids[key] = {event_id}

    def _unsubscribe_from_events(self: FSPAllModesComponentManager, fqdn: str):
        if fqdn in self.subscription_event_ids and fqdn in self._proxies and self._proxies[fqdn] is not None:
            for event_id in self.subscription_event_ids[fqdn]:
                try:
                    self._proxies[fqdn].unsubscribe_event(event_id)
                except Exception as ex:
                    self.logger.error(f"Unable to unsubcribe from event {event_id} for device server {fqdn}: {repr(ex)}")

    def proxies_health_state_change_event(self: FSPAllModesComponentManager, event_data: EventData):
        if event_data.err:
            self.logger.error(
                f"Problem occured when recieving healthState event for {event_data.device.dev_name()}. Unable to determine health state"
            )
            self.fhs_health_monitor.add_health_state(event_data.device.dev_name(), HealthState.UNKNOWN)
        else:
            self.fhs_health_monitor.add_health_state(event_data.device.dev_name(), event_data.attr_value.value)

    def _long_running_command_callback(self: FSPAllModesComponentManager, event: EventData):
        id, result = event.attr_value.value

        self.logger.info(
            f"FSP {self._fsp_id}: Long running command '{id}' on '{event.device.name()}' completed with result '{result}'"
        )
        if event.err:
            self.logger.error(f"FSP {self._fsp_id}: Long running command failed {event.errors}")
