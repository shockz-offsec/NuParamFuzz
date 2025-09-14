#!/bin/bash

# Rename and move NuParamFuzz.sh file to /usr/bin/npf
sudo cp NuParamFuzz.sh /usr/bin/npf

# Make the NuParamFuzz file executable
sudo chmod +x /usr/bin/npf

echo "NuParamFuzz has been installed successfully! Now Enter the command 'npf' to run the tool."

cd .. && rm -r NuParamFuzz