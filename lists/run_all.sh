cd /home/claude/halo-walk
for r in 20 50 100; do [ -f results/fidelity/fid_$r.json ] || python3 scenarios/fidelity.py $r results/fidelity/fid_$r.json; done > results/fidelity/fidelity.log 2>&1
bash scenarios/batch.sh lists/all.txt
echo ALL_DONE > results/ALL_DONE
