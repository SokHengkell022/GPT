LOG="$HOME/.satpol_log.txt"
log_and_exit() {
  local reason="$1"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $reason"
  sleep 1
  exit 0
#  pkill -9 -f "$kocak_kocak"
#  pkill -9 -f com.termux
}

akses() {
  if ! grep -q 'com.termux' /proc/$$/cmdline 2> /dev/null; then
    log_and_exit "ENV ERROR: Bukan dijalankan dari Termux"
  fi
}
akses
deteksi_dir() {
  cek="$HOME/Pasang/.git/refs/remotes/origin/HEAD"
  cek1="$HOME/Lubeban/.git/refs/remotes/origin/HEAD"
  if [[ ! -f "$cek" || ! -f "$cek1" ]]; then
    log_and_exit "DIR ERROR: Tidak ditemukan"
  fi
}

deteksi_debugger() {
  local suspicious_tools=("strace" "declare" "ltrace" "gdb" "lldb" "frida" "ida" "radare2" "ghidra" "bashdb")
  local script_path
  script_path=$(readlink -f "$0")
  local ppid_self
  ppid_self=$(awk '{print $4}' /proc/$$/stat 2> /dev/null)
  local parent_name
  parent_name=$(ps -p "$ppid_self" -o comm= 2> /dev/null)
  for tool in "${suspicious_tools[@]}"; do
    [[ "$parent_name" =~ $tool ]] && log_and_exit "DEBUGGER TOOL: Parent process suspicious: $parent_name"
    pgrep -x "$tool" > /dev/null && log_and_exit "DEBUGGER TOOL: Detected running $tool"
  done
  local pid=$$
  while :; do
    local ppid
    ppid=$(awk '{print $4}' /proc/$pid/stat 2> /dev/null)
    [[ -z "$ppid" || "$ppid" == "1" ]] && break
    local pname
    pname=$(ps -p "$ppid" -o comm= 2> /dev/null)
    for tool in "${suspicious_tools[@]}"; do
      [[ "$pname" =~ $tool ]] && log_and_exit "DEBUGGER CHAIN: Suspicious parent $pname"
    done
    pid=$ppid
  done
  local pids_running_script
  pids_running_script=$(pgrep -f "$script_path")
  for pid in $pids_running_script; do
    [[ "$pid" == "$$" ]] && continue
    local ppid
    ppid=$(awk '{print $4}' /proc/$pid/stat 2> /dev/null)
    local pname
    pname=$(ps -p "$ppid" -o comm= 2> /dev/null)
    for tool in "${suspicious_tools[@]}"; do
      [[ "$pname" =~ $tool ]] && log_and_exit "SCRIPT CLONE: $pname running same script"
    done
  done
}
deteksi_sniffer() {
  local sniffers=("tcpdump" "tshark" "ettercap" "ngrep" "wireshark" "fiddler" "charles")
  for sniffer in "${sniffers[@]}"; do
    if pgrep -x "$sniffer" > /dev/null; then
      log_and_exit "SNIFFER DETECTED: $sniffer aktif"
    fi
  done
  if lsof -p $$ 2> /dev/null | grep -q 'libtermux-net.so'; then
    log_and_exit "SNIFFER DETECTED: Akses libtermux-net.so"
  fi
}

deteksi_aktivitas_mencurigakan() {
  local perintah_mencurigakan=(
    'printf\|echo\|alias [a-zA-Z0-9]=\|set -x'
    'ELF'
    'tmp'
    'stav\|STAV\|S\.T\.A\.V\|s\.t\.a\.v\|bash-unofficial'
    'symbolic link to coreutils'
    'function\|aliased'
    '[a-zA-Z].*, [a-zA-Z].*, [a-zA-Z].* ·.*'
  )
  for pattern in "${perintah_mencurigakan[@]}"; do
    if history | grep -v "$$" | grep -Eiq "$pattern"; then
      log_and_exit "MENCURIGAKAN: History match $pattern"
    fi
  done

local suspicious_names=("printf" "stav" "bash-unofficial" "htop")
for pid in $(pgrep -f "python"); do
  if grep -qi "psutil" /proc/$pid/maps 2>/dev/null || grep -qi "psutil" /proc/$pid/cmdline 2>/dev/null; then
    log_and_exit "MENCURIGAKAN: Process mencurigakan ditemukan: $name"
  fi
done
for name in "${suspicious_names[@]}"; do
  if ps aux | grep -v "grep" | grep -v "$$" | grep -iq "$name"; then
    log_and_exit "MENCURIGAKAN: Process mencurigakan ditemukan: $name"
  fi
done
}

pantau_perubahan_file() {
  local file_penting=(
    "/data/data/com.termux/files/usr/bin/whoami"
    "/data/data/com.termux/files/usr/bin/id"
    "/data/data/com.termux/files/usr/bin/unzip"
    "/data/data/com.termux/files/usr/bin/openssl"
    "/data/data/com.termux/files/usr/bin/curl"
    "/data/data/com.termux/files/usr/bin/grep"
    "/data/data/com.termux/files/usr/bin/bash"
    "/data/data/com.termux/files/usr/bin/sh"
    "/system/bin/sh"
  )

  for file in "${file_penting[@]}"; do
    if [ -f "$file" ]; then
      if [ -L "$file" ]; then
        target=$(readlink -f "$file")
        if echo "$target" | grep -qE '/system/bin/(linker|linker64)'; then
          log_and_exit "SYMLINK WARNING: $file → $target (mengarah ke linker)"
        fi
      fi
      case "$file" in
        /tmp/* | /sdcard/* | /data/local/tmp/*)
          if file "$file" 2>/dev/null | grep -q 'ELF'; then
            log_and_exit "ELF WARNING: $file adalah ELF di lokasi tidak aman"
          fi
          ;;
      esac
      if file "$file" 2>/dev/null | grep -q 'ELF'; then
        if strings "$file" 2>/dev/null | grep -qE '/system/bin/(linker|linker64)'; then
          case "$file" in
            /data/data/com.termux/files/usr/bin/* | /system/bin/sh)
              ;;
            *)
              log_and_exit "ELF LINKER WARNING: $file mengandung linker (potensi inject)"
              ;;
          esac
        fi
      fi

    fi
  done
}
pip uninstall requests -y &> /dev/null
pip install requests &> /dev/null
main() {
  deteksi_dir
  deteksi_debugger
  deteksi_sniffer
  deteksi_aktivitas_mencurigakan
  pantau_perubahan_file
  aman_grep() {
    command grep "$@" | while read -r line; do
      case "$line" in
        *ELF* | *psutil* | *symbolic\ link\ to\ coreutils* | *stav* | *STAV* | *S.T.A.V*)
          log_and_exit "AMAN_GREP TRIGGERED: $line"
          ;;
        *)
          printf "%s\n" "$line"
          ;;
      esac
    done
  }

  echo -e "" | aman_grep . > /dev/null 2>&1
}
while true; do
main "$@"
sleep 2
done &> /dev/null &
AI_CHAT() {
  local CONFIG_FILE="$HOME/.Hina_AI"
  local CACHE_FILE="$HOME/.cache_ai_response"
  local HISTORY_FILE="$HOME/.history_ai"
  local USE_ESPEAK=true
  BOLD=$(tput bold)
  NORMAL=$(tput sgr0)
  RED=$(tput setaf 1)
  GREEN=$(tput setaf 2)
  CYAN=$(tput setaf 6)
  YELLOW=$(tput setaf 3)
  BLUE=$(tput setaf 4)

for pkg in curl jq perl boxes espeak cowsay ruby; do
  if ! command -v "$pkg" > /dev/null; then
    echo "${YELLOW}⏳ Menginstall: $pkg ...${NORMAL}"
    pkg install -y "$pkg" > /dev/null 2>&1
  fi
done
if ! command -v lolcat > /dev/null; then
  echo "${YELLOW}⏳ Menginstall: lolcat (via gem) ...${NORMAL}"
  gem install lolcat
fi

  mkdir -p "$(dirname "$CACHE_FILE")"
  mkdir -p "$(dirname "$HISTORY_FILE")"

  print_box() {
    local text="$1"
    echo -e "$text" | fold -sw 50 | boxes -d ansi-rounded
  }

  strip_emoji() {
    perl -CSDA -pe 's/[\p{Emoji_Presentation}\p{Extended_Pictographic}]//g'
  }

  sanitize_response() {
    local text="$1"
    text="${text//Siputzx Production!/GALIRUS OFFICIAL}"
    text="${text//luminAi!/DONGO AI}"
    echo "$text"
  }

  get_history_summary() {
    [ -f "$HISTORY_FILE" ] && tail -n 5 "$HISTORY_FILE" | sed 's/^/• /' || echo "Belum ada riwayat."
  }

  check_cache() {
    local prompt="$1"
    local key
    key=$(echo "$prompt" | md5sum | cut -d' ' -f1)
    if [ -f "$CACHE_FILE" ]; then
      local line
      line=$(grep "^$key|" "$CACHE_FILE")
      if [ -n "$line" ]; then
        local response="${line#*|}"
        echo -e "\n${CYAN}Pengguna:${NORMAL} $prompt"
        echo -e "${GREEN}AI:${NORMAL}"
        print_box "$response"
        echo "Pengguna: $prompt" >> "$HISTORY_FILE"
        echo "Respon: $response" >> "$HISTORY_FILE"
        [ "$USE_ESPEAK" = true ] && echo "$response" | strip_emoji | espeak -v id 2>/dev/null &
        return 0
      fi
    fi
    return 1
  }

  fetch_ai_response() {
    local prompt="$1"
    local history summary response data
    history=$(get_history_summary | tr '\n' ' ' | sed 's/"/\\"/g')
    summary="Berikut ringkasan: $history Pertanyaan: $prompt"
    response=$(curl --compressed -s --max-time 60 -X POST "https://api.siputzx.my.id/api/ai/meta-llama-33-70B-instruct-turbo" \
      -H "Content-Type: application/json" \
      -d "{\"content\": \"$summary\"}")
    if [ $? -ne 0 ] || [ -z "$response" ]; then
      print_box "❌ Gagal: Tidak bisa menghubungi server."
      return 1
    fi
    data=$(echo "$response" | jq -r '.data' 2>/dev/null)
    if [ -z "$data" ] || [ "$data" = "null" ]; then
      print_box "❌ Gagal: Respon kosong dari server."
      echo "$response" | fold -sw 60
      return 1
    fi
    data=$(sanitize_response "$data")
    echo -e "\n${CYAN}Pengguna:${NORMAL} $prompt"
    echo -e "${GREEN}AI:${NORMAL}"
    print_box "$data"
    [ "$USE_ESPEAK" = true ] && echo "$data" | strip_emoji | espeak -v id 2>/dev/null &
    local key
    key=$(echo "$prompt" | md5sum | cut -d' ' -f1)
    echo "$key|$data" >> "$CACHE_FILE"
    echo "Pengguna: $prompt" >> "$HISTORY_FILE"
    echo "Respon: $data" >> "$HISTORY_FILE"
  }
  handle_custom_response() {
    local input="$1"
    if echo "$input" | grep -qiE 'siapa.*membuat.*kamu|membuat.*kamu.*siapa|kamu.*dibuat.*oleh|siapa pencipta kamu'; then
      local custom="Saya dibuat oleh Galirus Official agar bisa dipergunakan untuk kalian para user Termux."
      echo -e "\n${CYAN}Pengguna:${NORMAL} $input"
      echo -e "${GREEN}AI:${NORMAL}"
      print_box "$custom"
      [ "$USE_ESPEAK" = true ] && echo "$custom" | strip_emoji | espeak -v id 2>/dev/null &
      echo "Pengguna: $input" >> "$HISTORY_FILE"
      echo "Respon: $custom" >> "$HISTORY_FILE"
      return 0
    fi
    return 1
  }

  clear
  cowsay -f eyes "DONGO AI - SUBSCRIBE GALIRUS OFFICIAL" | lolcat
  echo -e "\n${BLUE}${BOLD}   Selamat datang di DONGO AI Chat Terminal Galirus
   Jangan lupa sawer ADMIN${RED}:${CYAN}https://saweria.co/Galirus
${BLUE}   Ketik '${YELLOW}exit${BLUE}' untuk keluar.
   Ketik '${YELLOW}--mute${BLUE}' untuk menonaktifkan suara.
   Ketik '${YELLOW}--unmute${BLUE}' untuk mengaktifkan suara.${NORMAL}\n"

  while true; do
    echo -ne "${YELLOW}➤ ${NORMAL}"
    read -r prompt
    case "$prompt" in
      "exit")
        break
        ;;
      "--mute")
        USE_ESPEAK=false
        echo -e "${CYAN}🔇 Suara dinonaktifkan.${NORMAL}"
        continue
        ;;
      "--unmute")
        USE_ESPEAK=true
        echo -e "${CYAN}🔊 Suara diaktifkan.${NORMAL}"
        continue
        ;;
      "")
        continue
        ;;
    esac
    if handle_custom_response "$prompt"; then
      continue
    elif check_cache "$prompt"; then
      continue
    else
      fetch_ai_response "$prompt"
    fi
    echo
  done
  echo -e "${CYAN}👋 Sampai jumpa!${NORMAL}"
}
if [ -f "$PREFIXl/bin/AI" ]; then
AI_CHAT
else
cp -r AI $PREFIX/bin/
chmod +x "$PREFIX/bin/AI"
AI_CHAT
fi