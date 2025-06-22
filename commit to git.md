1. running this git add .
2. running this : git commit -m "name of file"
3. running this : git push -u origin main
4. check status: git status

'''
step by step to set up ssh key for the github:

1. open terminal and running this command 
ssh-keygen -t ed25519 -C "corodostudio@gmail.com" -> pressing enter and enter

2. sta the ssh-agent in the background running this on the terminal
eval "$(ssh-agent -s)"

3. add the configuration by running this:
nano ~/.ssh/config

4. pasting this info into the nano above:

Host github.com
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/id_ed25519

save by pressing Ctrl+x 
and then pressing Y

5. adding the ssh private key to the ssh-agent and store the passphrase in the keychain in the terminal
ssh-add --apple-use-keychain ~/.ssh/id_ed25519

6. running this command in the terminal: 
open ~/.ssh

7. find the extension in the .pub and open it with the vscode

8. copy the .pub and then pasting it to the github setting and add the new ssh key

9. give the name of the file and then pasting it

### short cut commit to git

'''
git add . && git commit -m "Quick update" && git push

or add this into the terminal: 

and then running this:

gpush

'''