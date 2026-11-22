cd /home/claude/halo-walk
while pgrep -f "scenarios/batch.sh lists/all.txt" >/dev/null; do sleep 10; done
cp lists/all.txt.next lists/all.txt
python3 analysis/stale_runs.py --move > lists/stale_final2.txt
bash scenarios/batch.sh lists/all.txt
echo DONE > results/FINAL_DONE
