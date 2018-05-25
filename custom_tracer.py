import frida
import threading
from colorama import Fore, Style
from frida.application import Reactor, ConsoleApplication, input_with_timeout
from frida.tracer import TracerProfileBuilder, Tracer, MemoryRepository, UI, FileRepository
import sys


def on_message(message, data):
    print(message)


class TracerApplication(ConsoleApplication, UI):
    def __init__(self):
        super(TracerApplication, self).__init__(self._await_ctrl_c)
        self._palette = [Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.GREEN, Fore.RED, Fore.BLUE]
        self._next_color = 0
        self._attributes_by_thread_id = {}
        self._last_event_tid = -1

    def _add_options(self, parser):
        pb = TracerProfileBuilder()

        def process_builder_arg(option, opt_str, value, parser, method, **kwargs):
            method(value)

        parser.add_option("-I", "--include-module", help="include MODULE", metavar="MODULE",
                          type='string', action='callback', callback=process_builder_arg,
                          callback_args=(pb.include_modules,))
        parser.add_option("-X", "--exclude-module", help="exclude MODULE", metavar="MODULE",
                          type='string', action='callback', callback=process_builder_arg,
                          callback_args=(pb.exclude_modules,))
        parser.add_option("-i", "--include", help="include FUNCTION", metavar="FUNCTION",
                          type='string', action='callback', callback=process_builder_arg, callback_args=(pb.include,))
        parser.add_option("-x", "--exclude", help="exclude FUNCTION", metavar="FUNCTION",
                          type='string', action='callback', callback=process_builder_arg, callback_args=(pb.exclude,))
        parser.add_option("-a", "--add", help="add MODULE!OFFSET", metavar="MODULE!OFFSET",
                          type='string', action='callback', callback=process_builder_arg,
                          callback_args=(pb.include_relative_address,))
        parser.add_option("-T", "--include-imports", help="include program's imports",
                          action='callback', callback=process_builder_arg, callback_args=(pb.include_imports,))
        parser.add_option("-t", "--include-module-imports", help="include MODULE imports", metavar="MODULE",
                          type='string', action='callback', callback=process_builder_arg,
                          callback_args=(pb.include_imports,))
        parser.add_option("-m", "--include-objc-method", help="include OBJC_METHOD", metavar="OBJC_METHOD",
                          type='string', action='callback', callback=process_builder_arg,
                          callback_args=(pb.include_objc_method,))
        parser.add_option("-s", "--include-debug-symbol", help="include DEBUG_SYMBOL", metavar="DEBUG_SYMBOL",
                          type='string', action='callback', callback=process_builder_arg,
                          callback_args=(pb.include_debug_symbol,))
        self._profile_builder = pb

    def _usage(self):
        return "usage: %prog [options] target"

    def _initialize(self, parser, options, args):
        self._tracer = None
        self._targets = None
        self._profile = self._profile_builder.build()

    def _needs_target(self):
        return True

    def _start(self):
        self._tracer = Tracer(self._reactor, FileRepository(self._reactor), self._profile, log_handler=self._log)
        try:
            self._targets = self._tracer.start_trace(self._session, self)
        except Exception as e:
            self._update_status("Failed to start tracing: {error}".format(error=e))
            self._exit(1)

    def _stop(self):
        self._tracer.stop()
        self._tracer = None

    def _await_ctrl_c(self, reactor):
        while reactor.is_running():
            try:
                input_with_timeout(0.5)
            except KeyboardInterrupt:
                break

    def on_trace_progress(self, operation):
        if operation == 'resolve':
            self._update_status("Resolving functions...")
        elif operation == 'instrument':
            self._update_status("Instrumenting functions...")
        elif operation == 'ready':
            if len(self._targets) == 1:
                plural = ""
            else:
                plural = "s"
            self._update_status("Started tracing %d function%s. Press Ctrl+C to stop." % (len(self._targets), plural))
            self._resume()

    def on_trace_error(self, error):
        self._print(Fore.RED + Style.BRIGHT + "Error" + Style.RESET_ALL + ": " + error['message'])

    def on_trace_events(self, events):
        no_attributes = Style.RESET_ALL
        for timestamp, thread_id, depth, target_address, message in events:
            indent = depth * "   | "
            attributes = self._get_attributes(thread_id)
            if thread_id != self._last_event_tid:
                self._print("%s           /* TID 0x%x */%s" % (attributes, thread_id, Style.RESET_ALL))
                self._last_event_tid = thread_id
            self._print("%6d ms  %s%s%s%s" % (timestamp, attributes, indent, message, no_attributes))

    def on_trace_handler_create(self, function, handler, source):
        self._print("%s: Auto-generated handler at \"%s\"" % (function, source.replace("\\", "\\\\")))

    def on_trace_handler_load(self, function, handler, source):
        self._print("%s: Loaded handler at \"%s\"" % (function, source.replace("\\", "\\\\")))

    def _get_attributes(self, thread_id):
        attributes = self._attributes_by_thread_id.get(thread_id, None)
        if attributes is None:
            color = self._next_color
            self._next_color += 1
            attributes = self._palette[color % len(self._palette)]
            if (1 + int(color / len(self._palette))) % 2 == 0:
                attributes += Style.BRIGHT
            self._attributes_by_thread_id[thread_id] = attributes
        return attributes


def _log(self, level, text):
    if level == 'info':
        self._print(text)
    else:
        color = Fore.RED if level == 'error' else Fore.YELLOW
        self._print(color + Style.BRIGHT + text + Style.RESET_ALL)


class Test(UI):
    def __init__(self, device):
        self._device = device

    def on_trace_progress(self, operation):
        print(operation)
        device.resume("Gadget")

    def on_trace_error(self, error):
        print(error)

    def on_trace_events(self, events):
        print(events)

    def on_trace_handler_create(self, function, handler, source):
        print("super !")

    def on_trace_handler_load(self, function, handler, source):
        print(function)


device = frida.get_usb_device(3)  # added timeout to wait for 3 seconds
session = device.attach("Gadget")
reactor = Reactor(None)
repo = FileRepository(reactor)
pb = TracerProfileBuilder()
pb.include("open*")
profile = pb.build()
tracer = Tracer(reactor, repo, profile, _log)
ui = Test(device)
try:
    tracer.start_trace(session, ui)
except Exception as e:
    print(e)

# app = TracerApplication()
# app.run()
