cd /home/claude/halo-walk
until [ -f results/ALL_DONE ]; do sleep 20; done
python3 analysis/stale_runs.py --move > lists/redo_auto.txt
bash scenarios/batch.sh lists/redo_auto.txt
echo DONE > results/REDO_DONE
