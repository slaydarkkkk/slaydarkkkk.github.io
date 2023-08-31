git.exe add . && echo "[1] added" \
&& git.exe commit -m "update" && echo "[2] commited" \
&& eval $(ssh-agent -s) && ssh-add ~/.ssh/id_slaydark && echo "[3] add key" \
&& /usr/bin/git push && echo "[4] pushed"