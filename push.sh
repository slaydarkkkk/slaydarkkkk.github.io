git add . && git commit -m "update" && eval $(ssh-agent -s) \
&& ssh-add ~/.ssh/id_slaydark && /usr/bin/git push