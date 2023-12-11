CI with GitHub Actions Notes
================
Tracking the things I did to use and locally run CI builds with GitHub Actions.

* Local build: Use [Nectos/Act](https://github.com/nektos/act) run to GitHub Actions locally.

  Some common commands:
  * The command below will look in `.github/workflows` for a `.yml` file containing a `job` with id: `build`, and run that job:

        act -j build
  
    Some more commands:
  
        act -j build-nightly

    Use locally configured vars/secrets:

        act -j build --env-file .github/vars.env --secret-file .github/secrets.env
  
Misc
----

* Setup Branch Protections (*NOPE* - Branch Protections break ability to push during a job)
  
  see Settings -> Branches -> Branch protection rules -> `main` ->
  
  Under: "Protect matching branches"

  Check: `Require status checks to pass before merging`

  Check: `Require branches to be up to date before merging`

  Under "Status checks that are required.", ensure this line exists: 
  
   `Build Installer` -> "GitHub Actions" 

  Note: `Build Installer` maps directly to the job with that `name` in the file: [build_and_release.yml](./workflows/build_and_release.yml).
