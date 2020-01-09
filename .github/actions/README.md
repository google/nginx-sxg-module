# Debian related build actions

Automatically generated Github action settings are here (.github/actions/).
We need several .deb files for various debian based environments respectivelly.
We wanted to use --build-args to switch the base environments of dockerfiles, but `build-args` are not supported by Github actions for now.
https://github.community/t5/GitHub-Actions/Feature-Request-Build-args-support-in-Docker-container-actions/td-p/37802
We plan to migrate it to use build-args feature after Github support it.
