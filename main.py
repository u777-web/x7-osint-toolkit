import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tqdm import tqdm
from banner import render, menu, prompt, print_line, c, C_MUTED, C_DIM
from modules import (
    username_enum, breach_check, correlation, ip_geo, about,
    social_recon, phone_lookup, email_lookup, domain_network,
    metadata_extractor, crypto_wallet, reverse_image, mac_lookup,
    paste_monitor,
)

MODULES = {
    "1":  username_enum,
    "2":  breach_check,
    "3":  correlation,
    "4":  ip_geo,
    "5":  social_recon,
    "6":  phone_lookup,
    "7":  email_lookup,
    "8":  domain_network,
    "9":  metadata_extractor,
    "10": crypto_wallet,
    "11": reverse_image,
    "12": mac_lookup,
    "13": paste_monitor,
    "14": about,
}

BAR_FMT = "\033[38;5;245m  {desc} |{bar}| {percentage:3.0f}%\033[0m"


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def boot_sequence():
    for _ in tqdm(range(20), desc="initializing", ncols=60,
                  bar_format=BAR_FMT):
        time.sleep(0.012)
    print()


def main():
    clear()
    boot_sequence()

    while True:
        clear()
        render()
        menu()
        choice = prompt()

        if choice == "15" or choice.lower() in ("exit", "quit", "q"):
            print_line("  bye.", code=C_MUTED)
            break

        mod = MODULES.get(choice)
        if not mod:
            print_line("  [!] invalid selection", code=C_DIM, delay=0)
            input(c(C_DIM, "  enter to continue..."))
            continue

        print()
        try:
            mod.run()
        except KeyboardInterrupt:
            print_line("  [!] interrupted", code=C_DIM, delay=0)
        except Exception as e:
            print_line(f"  [!] module error: {e}", code=C_DIM, delay=0)

        input(c(C_DIM, "  enter to continue..."))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")