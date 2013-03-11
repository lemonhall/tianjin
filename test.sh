cat brew_staff | while read STAFF

do
	brew info $STAFF >1

	COUNT=0
	cat 1 | while read LINE
	do
		let COUNT++
		if [ $COUNT -eq 2 ]; 
		then
			echo "<a href='$LINE'>$STAFF</a>"
		fi
	done
done 
