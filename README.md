dnf list installed | awk '{print $NF}' | grep "^@" | sort | uniq -c | sort -nr
