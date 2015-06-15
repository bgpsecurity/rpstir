## Handle $(CLEANDIRS)


clean-local: clean-local-cleandirs
.PHONY: clean-local-cleandirs
clean-local-cleandirs:
	rm -rf $(CLEANDIRS)
