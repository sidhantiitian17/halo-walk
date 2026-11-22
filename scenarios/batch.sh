#!/bin/bash
# run a list of "<scenario> <config> <rep>" lines sequentially (inside the VM); resumable
cd /home/claude/halo-walk
LIST=$1; LOG=results/batch_$(basename $LIST).log
while read sc cf rp; do
  [ -z "$sc" ] && continue
  d=results/raw/$sc/$cf/$(printf r%02d $rp)
  [ -f $d/meta.json ] && grep -q '"end"' $d/meta.json && continue
  echo "$(date +%T) START $sc $cf $rp" >> $LOG
  timeout 400 python3 scenarios/run.py $sc $cf $rp >> $LOG 2>&1 || { echo "FAILED $sc $cf $rp" >> $LOG; ./rig/rig_down.sh; }
done < $LIST
echo "BATCH DONE $(date +%T)" >> $LOG
