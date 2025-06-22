### adding tag to git commit
```bash
git tag -a v1.0 -m "version 1.0"
```
### push tag to remote
```bash
git push origin v1.0
```
### delete tag locally
```bash
git tag -d v1.0
```
### delete tag remotely
```bash
git push origin :refs/tags/v1.0
```
### list all tags
```bash
git tag
```
### list all tags with details
```bash

### git add .
```bash
git add . && git commit -m "your commit message" && git tag -a v1.0 -m "version 1.0" && git push origin v1.0
git show-ref --tags
```