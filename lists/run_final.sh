cd /home/claude/halo-walk
python3 analysis/stale_runs.py --move > lists/stale_final.txt
bash scenarios/batch.sh lists/all.txt
echo DONE > results/FINAL_DONE
