from kuma1to2 import *
import PySimpleGUI as sg
import threading
import os


def main():
    system_msg = sg.Multiline(
        "msg: please fill in the blanks\n",
        text_color="gray", size=(60, 10), autoscroll=True)
    password_input = sg.Input("", disabled=True)
    ok_button = sg.OK()

    layout = [
        [sg.Text("warning: Do not forget backup original wallet!", text_color="red")],
        [
            sg.Text("you need set password below if encrypt wallet"),
            sg.Checkbox("encrypted", enable_events=True, default=False),
        ],
        [password_input],
        [sg.Text("wallet.dat"), sg.Input(), sg.FileBrowse()],
        [
            sg.Text("endpoint"),
            sg.Input("http", size=(10, None)),
            sg.Text("://"),
            sg.Input("127.0.0.1", size=(10, None)),
            sg.Text(":"),
            sg.Input("3000", size=(6, None))
        ],
        [
            sg.Text("authentication"),
            sg.Input("user", size=(20, None)),
            sg.Text(":"),
            sg.Input("password", size=(20, None)),
        ],
        [
            sg.Text("human readable part(hrp)"),
            sg.Input("test", size=(20, None)),
        ],
        [sg.Text("system message")],
        [system_msg],
        [ok_button, sg.CloseButton("close")],
    ]
    window = sg.Window("kumacoin 1.0⇒2.0 swapper (%s)" % __version__,
                       layout, debugger_enabled=False)
    window.read_call_from_debugger = True

    while True:
        try:
            event, values = window.read()
            if event in (None, 'close'):
                # if user closes window or clicks cancel
                break
            if event == 0:
                # checkbox
                password_input.update(disabled=not values[event])
                continue
            if event != "OK":
                system_msg.update("warning unknown event `%s`\n" % event, append=True)
                continue

            # setup params
            password = values[1] if values[0] else ""
            system_msg.update("msg: password=`%s`\n" % password, append=True)
            wallet_path = values[2]
            system_msg.update("msg: wallet=`%s`\n" % wallet_path, append=True)
            url = "%s://%s:%s@%s:%s/private/importprivatekey" \
                  % (values[3], values[6], values[7], values[4], values[5])
            system_msg.update("msg: url=`%s`\n" % url, append=True)
            hrp = values[8]
            system_msg.update("msg: hrp=`%s`\n" % hrp, append=True)

            # check
            if not os.path.exists(wallet_path):
                system_msg.update("error: not found wallet.dat\n", append=True)
                continue
            if not os.path.isfile(wallet_path):
                system_msg.update("error: path is not file\n", append=True)
                continue

            # search
            threading.Thread(
                target=task, args=(password, wallet_path, hrp, url, system_msg, ok_button)).start()
        except Exception as e:
            system_msg.update("error: `%s`\n" % str(e), append=True)


if __name__ == '__main__':
    main()
