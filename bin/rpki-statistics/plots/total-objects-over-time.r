data <- read.table('total-objects-over-time.dat', sep="\t", header=TRUE)

times <- read.table('times.dat', sep="\t", header=TRUE)
times$Start <- as.POSIXlt(times$Start)
times$End <- as.POSIXlt(times$End)

x <- times$Start + difftime(times$End, times$Start) / 2
y <- data$CACerts + data$CRLs + data$ROAs + data$MFTs

png('total-objects-over-time.png', width=1600, height=1200, pointsize=24)
plot(x, y, type="o",
    main="Total Number of Objects",
    xlab="Time (UTC)",
    ylab="Number of Objects",
    ylim=c(0,max(y)))
dev.off()
