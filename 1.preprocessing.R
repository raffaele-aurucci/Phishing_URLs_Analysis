# PRE-PROCESSING REAL DATASET
# Author: Raffaele Aurucci

# install.packages("moments")

library(moments)
library(utils)

df <- read.csv('./datasets/Phishing_URL_Dataset_3.csv', sep = ";")

View(df)

# ------------------------------------------------------------------------------
#                               PRE-PROCESSING

# RQ1: What characteristics of the observed phenomenon provide the greatest 
# discriminatory information for identifying phishing sites compared to 
# legitimate ones?
# ------------------------------------------------------------------------------


# count NA values
labels = names(df)

for (label in labels) {
  na_count <- sum(is.na(df[[label]]))
  print(paste(label, ":", na_count))
}

# delete duplicated observations
df <- df[!duplicated(df), ]

# reset indices
row.names(df) <- NULL

# moda function
moda <- function(x) {
  ux <- unique(x)
  ux[which.max(tabulate(match(x, ux)))]
}

# ------------------------------------------------------------------------------
# ATTRIBUTE 'label'

# 0 -> phishing URL
# 1 -> legitimate URL

table(df$label)

# undersampling to balance dataset
indices_label_1 <- which(df$label == 1)
indices_to_remove <- sample(indices_label_1, 3427)
df <- df[-indices_to_remove, ]
row.names(df) <- NULL

df_0 <- df[df$label == 0, ]
df_1 <- df[df$label == 1, ]

# ------------------------------------------------------------------------------
# ATTRIBUTE 'FILENAME' 

# delete attribute
df <- subset(df, select = -FILENAME)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'URL'

# delete duplicated observations
df <- df[!duplicated(df$URL), ]

# delete attribute because have only unique value
df <- subset(df, select = -URL)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'Domain'

# delete attribute because have only unique value
df <- subset(df, select = -Domain)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'TLD'

tld_table <- table(df$TLD)
tld_table

tld_df <- as.data.frame(tld_table)
tld_filtered <- tld_df[tld_df$Freq >= 100, ]

# the most frequent TLD category is 'com'
tld_max = moda(df$TLD)
tld_max

filtered_df <- df[df$TLD %in% tld_filtered$Var1, ]
label_counts <- prop.table(table(filtered_df$label, filtered_df$TLD))
label_counts

barplot(label_counts, col = c('orange', 'lightblue'), 
     main = 'Frequenza relativa congiunta TLD',
     legend = c('phishing', 'legitimate'))

# TARGET ENCODING
# transform this feature with probability of legitimate TLD
# for each TLD: 
#   (sum of value label) / (sum of TLD element)

tld_encoding <- aggregate(label ~ TLD, data = df, FUN = mean)
colnames(tld_encoding)[2] <- "TLDEncoding"
df <- merge(df, tld_encoding, by = "TLD", all.x = TRUE)
df <- df[, -which(names(df) == "TLD")]
df <- df[, c(1, 2, ncol(df), 3:(ncol(df) - 1))]

df_0 <- df[df$label == 0, ]
df_1 <- df[df$label == 1, ]

# DISPERSION
summary(df$TLDEncoding)
var(df$TLDEncoding)
sd(df$TLDEncoding)

# DISTRIBUTION
breaks <- c(-1, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0)

labels <- c("[0-0.1]", "(0.1-0.2]", "(0.2-0.3]", "(0.3-0.4]", "(0.4-0.5]",
            "(0.5-0.6]", "(0.6-0.7]", "(0.7-0.8]", "(0.8-0.9]", "(0.9-1.0]")
 
j_freq <- table(df$label, cut(df$TLDEncoding, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta TLDEncoding")

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$TLDEncoding)
kurtosis_value_0 <- kurtosis(df_0$TLDEncoding)

skw_value_1 <- skewness(df_1$TLDEncoding)
kurtosis_value_1 <- kurtosis(df_1$TLDEncoding)

density_0 <- density(df_0$TLDEncoding)
density_1 <- density(df_1$TLDEncoding)

# 1 row, 2 columns
par(mfrow = c(1, 2))

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "TLDEncoding", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright",
       legend = c(paste("Skewness:", round(skw_value_0, 2)),
                  paste("Kurtosis:", round(kurtosis_value_0, 2))),
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "TLDEncoding", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright",
       legend = c(paste("Skewness:", round(skw_value_1, 2)),
                  paste("Kurtosis:", round(kurtosis_value_1, 2))),
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$TLDEncoding, df$label)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'URLLenght'

summary(df$URLLength)

breaks <- c(0, 10, 20, 30, 40, 50, 1000) 

j_freq <- table(df$label, cut(df$URLLength, breaks = breaks))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta URLLenght")

# OUTLIERS
summary(df_0$URLLength)
summary(df_1$URLLength)

boxplot(df_0$URLLength, df_1$URLLength, 
        ylim = c(min(df_0$URLLength), quantile(df_0$URLLength, 0.95)),
        main = 'Boxplot URLLenght', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))

# IQR FOR 'URLLength'
q1 <- quantile(df$URLLength, 0.25)
q3 <- quantile(df$URLLength, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$URLLength < lower_bound | df$URLLength > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$URLLength, 0.25)
q3_0 <- quantile(df_0$URLLength, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$URLLength < lower_bound_0 | df_0$URLLength > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$URLLength, 0.25)
q3_1 <- quantile(df_1$URLLength, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$URLLength < lower_bound_1 | df_1$URLLength > upper_bound_1)

outliers_0  
outliers_1 


# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$URLLength, 0.75) - quantile(df_0$URLLength, 0.25)
M1_0 <- quantile(df_0$URLLength, 0.5) - 1.57*IQR_0/sqrt(length(df_0$URLLength))
M2_0 <- quantile(df_0$URLLength, 0.5) + 1.57*IQR_0/sqrt(length(df_0$URLLength))

IQR_1 <- quantile(df_1$URLLength, 0.75) - quantile(df_1$URLLength, 0.25)
M1_1 <- quantile(df_1$URLLength, 0.5) - 1.57*IQR_1/sqrt(length(df_1$URLLength))
M2_1 <- quantile(df_1$URLLength, 0.5) + 1.57*IQR_1/sqrt(length(df_1$URLLength))

# no overlap: the median is different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)


# DISPERSION
var(df$URLLength)
sd(df$URLLength)


# DISTRIBUTION FORM
skw_value <- skewness(df$URLLength)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$URLLength)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$URLLength)
h_sturges <- (max(df$URLLength) - min(df$URLLength)) / sqrt(n)
density_sturges <- density(df$URLLength, bw = h_sturges)

plot(density_sturges, main = "Distribuzione URLLength", 
     col = "orange", lwd = 2, xlab = 'URLLength')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)


# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$URLLength)
kurtosis_value_0 <- kurtosis(df_0$URLLength)

skw_value_1 <- skewness(df_1$URLLength)
kurtosis_value_1 <- kurtosis(df_1$URLLength)

# calculate sturges bandwidth for dataset phishing (outliers)
n_0 <- length(df_0$URLLength)
h_sturges_0 <- (max(df_0$URLLength) - min(df_0$URLLength)) / sqrt(n_0)
density_sturges_0 <- density(df_0$URLLength, bw = h_sturges_0, to=200)

density_1 <- density(df_1$URLLength)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_sturges_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "URLLength", ylab = "Density",
     ylim = c(0, max(density_sturges_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "URLLength", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$URLLength, df$label)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'DomainLenght'

summary(df$DomainLength)

breaks <- c(0, 10, 20, 30, 40, 50, 100) 

j_freq <- table(df$label, cut(df$DomainLength, breaks = breaks))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta DomainLength")

# OUTLIERS
summary(df_0$DomainLength)
summary(df_1$DomainLength)

boxplot(df_0$DomainLength, df_1$DomainLength,
        main = 'Boxplot DomainLength', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))

# IQR FOR 'DomainLength'
q1 <- quantile(df$DomainLength, 0.25)
q3 <- quantile(df$DomainLength, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$DomainLength < lower_bound | df$DomainLength > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$DomainLength, 0.25)
q3_0 <- quantile(df_0$DomainLength, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$DomainLength < lower_bound_0 | df_0$DomainLength > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$DomainLength, 0.25)
q3_1 <- quantile(df_1$DomainLength, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$DomainLength < lower_bound_1 | df_1$DomainLength > upper_bound_1)

outliers_0  
outliers_1 


# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$DomainLength, 0.75) - quantile(df_0$DomainLength, 0.25)
M1_0 <- quantile(df_0$DomainLength, 0.5) - 1.57*IQR_0/sqrt(length(df_0$DomainLength))
M2_0 <- quantile(df_0$DomainLength, 0.5) + 1.57*IQR_0/sqrt(length(df_0$DomainLength))

IQR_1 <- quantile(df_1$DomainLength, 0.75) - quantile(df_1$DomainLength, 0.25)
M1_1 <- quantile(df_1$DomainLength, 0.5) - 1.57*IQR_1/sqrt(length(df_1$DomainLength))
M2_1 <- quantile(df_1$DomainLength, 0.5) + 1.57*IQR_1/sqrt(length(df_1$DomainLength))

# no overlap: the median is different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)


# DISPERSION
var(df$DomainLength)
sd(df$DomainLength)


# DISTRIBUTION FORM
skw_value <- skewness(df$DomainLength)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$DomainLength)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$DomainLength)
h_sturges <- (max(df$DomainLength) - min(df$DomainLength)) / sqrt(n)
density_sturges <- density(df$DomainLength, bw = h_sturges)

plot(density_sturges, main = "Distribuzione DomainLength", 
     col = "orange", lwd = 2, xlab = 'DomainLenght')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)


# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$DomainLength)
kurtosis_value_0 <- kurtosis(df_0$DomainLength)

skw_value_1 <- skewness(df_1$DomainLength)
kurtosis_value_1 <- kurtosis(df_1$DomainLength)

density_0 <- density(df_0$DomainLength)
density_1 <- density(df_1$DomainLength)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density(df_0$DomainLength), main = "phishing",
     col = "orange", lwd = 2, xlab = "DomainLength", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "DomainLength", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$DomainLength, df$label)
# ------------------------------------------------------------------------------
# ATTRIBUTE 'IsDomainIP'

table(df$IsDomainIP)

cor(df$IsDomainIP, df$label)

# delete attribute because have only 81 value setting to 1
df <- subset(df, select = -IsDomainIP)
# ------------------------------------------------------------------------------
# ATTRIBUTE 'URLSimilarityIndex'

summary(df$URLSimilarityIndex)

breaks <- c(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100) 

j_freq <- table(df$label, cut(df$URLSimilarityIndex, breaks = breaks))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta URLSimilarityIndex")


# OUTLIERS
summary(df_0$URLSimilarityIndex)
summary(df_1$URLSimilarityIndex)


# DISPERSION 
var(df$URLSimilarityIndex)
sd(df$URLSimilarityIndex)

# CORRELATIONS WITH TARGET: ~0.85
cor(df$URLSimilarityIndex, df$label)

# values from 0 to 100

# delete this feature because:
# It's an heuristic calculated by authors of dataset
# It depends to a repository of Legitimate URL (dataset specific) 
# It's strongly discriminating
# 50% of data is setting to 100 (the legitimate URL is into previous repository)

df <- subset(df, select = -URLSimilarityIndex)
#-------------------------------------------------------------------------------
# ATTRIBUTE 'CharContinuationRate'

# delete this feature because:
# It's an heuristic not detailed calculated by authors of dataset 
# It depends to a repository of Phishing/Legitimate URL (dataset specific)

df <- subset(df, select = -CharContinuationRate)
#-------------------------------------------------------------------------------
# ATTRIBUTE 'TLDLegitimateProb'

# delete this feature because:
# It's an heuristic calculated by authors of dataset
# It depends to a repository of Legitimate URL (dataset specific) 

df <- subset(df, select = -TLDLegitimateProb)
#-------------------------------------------------------------------------------
# ATTRIBUTE 'URLCharProb'

# It's ambiguous feature, calculated by an heuristic not detailed 
# (probability not esplicated)
# It depends to a repository of Phishing/Legitimate URL (dataset specific)

df <- subset(df, select = -URLCharProb)
#-------------------------------------------------------------------------------
# ATTRIBUTE 'URLTitleMatchScore'

summary(df$URLTitleMatchScore)

breaks <- c(-1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100) 

labels <- c("[0,10]", "(10-20]", "(20-30]", "(30-40]", "(40-50]", "(50-60]", 
            "(60-70]", "(70-80]", "(80-90]", "(90-100]")

j_freq <- table(df$label, cut(df$URLTitleMatchScore, breaks = breaks, 
                              labels = labels))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta URLTitleMatchScore")

# transform this feature follow its score value
# 0  -> score == 0      (no match)
# 1  -> 0 < score < 100 (at least a match)
# 2  -> score == 100.   (complete match)

# df$URLTitleMatchScore[df$URLTitleMatchScore == 0] <- 0
# df$URLTitleMatchScore[df$URLTitleMatchScore > 0 & df$URLTitleMatchScore < 100] <- 1
# df$URLTitleMatchScore[df$URLTitleMatchScore == 100] <- 2
# 
# j_freq <- table(df$label, df$URLTitleMatchScore)
# j_freq_rel <- prop.table(j_freq)
# j_freq_rel
# 
# barplot(j_freq_rel, col = c("orange", "lightblue"),
#         legend = c("phishing", "legitimate"),
#         main = "Frequenza relativa congiunta URLTitleMatchScore",
#         names.arg = c('score = 0', '0 < score < 100', 'score = 100'))

# OUTLIERS
summary(df_0$URLTitleMatchScore)
summary(df_1$URLTitleMatchScore)

boxplot(df_0$URLTitleMatchScore, df_1$URLTitleMatchScore,
        main = 'Boxplot URLTitleMatchScore', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))

# IQR FOR 'URLTitleMatchScore'
q1 <- quantile(df$URLTitleMatchScore, 0.25)
q3 <- quantile(df$URLTitleMatchScore, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$URLTitleMatchScore < lower_bound | df$URLTitleMatchScore > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$URLTitleMatchScore, 0.25)
q3_0 <- quantile(df_0$URLTitleMatchScore, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$URLTitleMatchScore < lower_bound_0 | df_0$URLTitleMatchScore > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$URLTitleMatchScore, 0.25)
q3_1 <- quantile(df_1$URLTitleMatchScore, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$URLTitleMatchScore < lower_bound_1 | df_1$URLTitleMatchScore > upper_bound_1)

outliers_0  
outliers_1 

# DISPERSION 
var(df$URLTitleMatchScore)
sd(df$URLTitleMatchScore)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$URLTitleMatchScore)
kurtosis_value_0 <- kurtosis(df_0$URLTitleMatchScore)

skw_value_1 <- skewness(df_1$URLTitleMatchScore)
kurtosis_value_1 <- kurtosis(df_1$URLTitleMatchScore)

density_0 <- density(df_0$URLTitleMatchScore)
density_1 <- density(df_1$URLTitleMatchScore)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "URLTitleMatchScore", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "URLTitleMatchScore", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$URLTitleMatchScore, df$label)
#-------------------------------------------------------------------------------
# ATTRIBUTE 'DomainTitleMatchScore'

summary(df$DomainTitleMatchScore)

breaks <- c(-1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100) 

labels <- c("[0,10]", "(10-20]", "(20-30]", "(30-40]", "(40-50]", "(50-60]", 
            "(60-70]", "(70-80]", "(80-90]", "(90-100]")

j_freq <- table(df$label, cut(df$DomainTitleMatchScore, breaks = breaks, 
                              labels = labels))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta DomainTitleMatchScore")

# transform this feature follow its score value
# 0  -> score == 0      (no match)
# 1  -> 0 < score < 100 (at least a match)
# 2  -> score == 100.   (complete match)

# df$DomainTitleMatchScore[df$DomainTitleMatchScore == 0] <- 0
# df$DomainTitleMatchScore[df$DomainTitleMatchScore > 0 & df$DomainTitleMatchScore < 100] <- 1
# df$DomainTitleMatchScore[df$DomainTitleMatchScore == 100] <- 2
# 
# j_freq <- table(df$label, df$DomainTitleMatchScore)
# j_freq_rel <- prop.table(j_freq)
# j_freq_rel
# 
# barplot(j_freq_rel, col = c("orange", "lightblue"),
#         legend = c("phishing", "legitimate"),
#         main = "Frequenza relativa congiunta DomainTitleMatchScore",
#         names.arg = c('score = 0', '0 < score < 100', 'score = 100'))

# OUTLIERS
summary(df_0$DomainTitleMatchScore)
summary(df_1$DomainTitleMatchScore)

boxplot(df_0$DomainTitleMatchScore, df_1$DomainTitleMatchScore,
        main = 'Boxplot DomainTitleMatchScore', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))

# IQR FOR 'DomainTitleMatchScore'
q1 <- quantile(df$DomainTitleMatchScore, 0.25)
q3 <- quantile(df$DomainTitleMatchScore, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$DomainTitleMatchScore < lower_bound | df$DomainTitleMatchScore > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$DomainTitleMatchScore, 0.25)
q3_0 <- quantile(df_0$DomainTitleMatchScore, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$DomainTitleMatchScore < lower_bound_0 | df_0$DomainTitleMatchScore > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$DomainTitleMatchScore, 0.25)
q3_1 <- quantile(df_1$DomainTitleMatchScore, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$DomainTitleMatchScore < lower_bound_1 | df_1$DomainTitleMatchScore > upper_bound_1)

outliers_0  
outliers_1 

# DISPERSION 
var(df$DomainTitleMatchScore)
sd(df$DomainTitleMatchScore)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$DomainTitleMatchScore)
kurtosis_value_0 <- kurtosis(df_0$DomainTitleMatchScore)

skw_value_1 <- skewness(df_1$DomainTitleMatchScore)
kurtosis_value_1 <- kurtosis(df_1$DomainTitleMatchScore)

density_0 <- density(df_0$DomainTitleMatchScore)
density_1 <- density(df_1$DomainTitleMatchScore)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "DomainTitleMatchScore", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "DomainTitleMatchScore", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$DomainTitleMatchScore, df$label)

# TODO: study correlation with URLTitleMatchScore
#-------------------------------------------------------------------------------
# ATTRIBUTE 'TLDLenght'

summary(df$TLDLength)

j_freq <- table(df$label, 
                cut(df$TLDLength,
                    breaks = c(1, 2, 3, 4, 13), 
                    labels = c("2", "3", "4", "5-13"), 
                    right = TRUE))

j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta TLDLength")

# OUTLIERS
summary(df_0$TLDLength)
summary(df_1$TLDLength)

boxplot(df_0$TLDLength, df_1$TLDLength,
        main = 'Boxplot TLDLength', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))

# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$TLDLength, 0.75) - quantile(df_0$TLDLength, 0.25)
M1_0 <- quantile(df_0$TLDLength, 0.5) - 1.57*IQR_0/sqrt(length(df_0$TLDLength))
M2_0 <- quantile(df_0$TLDLength, 0.5) + 1.57*IQR_0/sqrt(length(df_0$TLDLength))

IQR_1 <- quantile(df_1$TLDLength, 0.75) - quantile(df_1$TLDLength, 0.25)
M1_1 <- quantile(df_1$TLDLength, 0.5) - 1.57*IQR_1/sqrt(length(df_1$TLDLength))
M2_1 <- quantile(df_1$TLDLength, 0.5) + 1.57*IQR_1/sqrt(length(df_1$TLDLength))

# overlap: the median isn't different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)

# DISPERSION 
var(df$TLDLength)
sd(df$TLDLength)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$TLDLength)
kurtosis_value_0 <- kurtosis(df_0$TLDLength)

skw_value_1 <- skewness(df_1$TLDLength)
kurtosis_value_1 <- kurtosis(df_1$TLDLength)

density_0 <- density(df_0$TLDLength)
density_1 <- density(df_1$TLDLength)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "TLDLength", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "TLDLength", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$TLDLength, df$label)

# delete this feature becasue has lower variance, overlap median and corr = 0

df <- subset(df, select = -TLDLength)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfSubDomain

summary(df$NoOfSubDomain)

j_freq <- table(df$label, df$NoOfSubDomain)
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfSubDomain")

# OUTLIERS
summary(df_0$NoOfSubDomain)
summary(df_1$NoOfSubDomain)

boxplot(df_0$NoOfSubDomain, df_1$NoOfSubDomain,
        main = 'Boxplot NoOfSubDomain', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))

# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$NoOfSubDomain, 0.75) - quantile(df_0$NoOfSubDomain, 0.25)
M1_0 <- quantile(df_0$NoOfSubDomain, 0.5) - 1.57*IQR_0/sqrt(length(df_0$NoOfSubDomain))
M2_0 <- quantile(df_0$NoOfSubDomain, 0.5) + 1.57*IQR_0/sqrt(length(df_0$NoOfSubDomain))

IQR_1 <- quantile(df_1$NoOfSubDomain, 0.75) - quantile(df_1$NoOfSubDomain, 0.25)
M1_1 <- quantile(df_1$NoOfSubDomain, 0.5) - 1.57*IQR_1/sqrt(length(df_1$NoOfSubDomain))
M2_1 <- quantile(df_1$NoOfSubDomain, 0.5) + 1.57*IQR_1/sqrt(length(df_1$NoOfSubDomain))

# overlap: the median isn't different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)

# DISPERSION 
var(df$NoOfSubDomain)
sd(df$NoOfSubDomain)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$NoOfSubDomain)
kurtosis_value_0 <- kurtosis(df_0$NoOfSubDomain)

skw_value_1 <- skewness(df_1$NoOfSubDomain)
kurtosis_value_1 <- kurtosis(df_1$NoOfSubDomain)

density_0 <- density(df_0$NoOfSubDomain)
density_1 <- density(df_1$NoOfSubDomain)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "NoOfSubDomain", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "NoOfSubDomain", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$NoOfSubDomain, df$label)

df <- subset(df, select = -NoOfSubDomain)
#-------------------------------------------------------------------------------
# ATTRIBUTE HasObfuscation

table(df$HasObfuscation)

# CORRELATION WITH TARGET
cor(df$HasObfuscation, df$label)

df <- subset(df, select = -HasObfuscation)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfObfuscatedChar

summary(df$NoOfObfuscatedChar)

table(NoOfObfuscatedChar = ifelse(df$NoOfObfuscatedChar == 0, "0", ">0"),
      label = df$label)

# DISPERSION 
var(df$NoOfObfuscatedChar)
sd(df$NoOfObfuscatedChar)

# CORRELATION WITH TARGET
cor(df$NoOfObfuscatedChar, df$label)

df <- subset(df, select = -NoOfObfuscatedChar)
#-------------------------------------------------------------------------------
# ATTRIBUTE ObfuscationRatio

summary(df$ObfuscationRatio)

table(ObfuscationRatio = ifelse(df$ObfuscationRatio == 0, "0", ">0"),
      label = df$label)

# DISPERSION 
var(df$ObfuscationRatio)
sd(df$ObfuscationRatio)

# CORRELATION WITH TARGET
cor(df$ObfuscationRatio, df$label)

df <- subset(df, select = -ObfuscationRatio)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfLettersInURL

summary(df$NoOfLettersInURL)

breaks <- c(-1, 10, 20, 30, 40, 50, 60, 70, 80, 100, 150, 700) 

labels <- c("[0-10]", "(10-20]", "(20-30]", "(30-40]", "(40-50]", "(50-60]", 
            "(60-70]", "(70-80]", "(80-100]", "(100-150]", "(150-700]")

j_freq <- table(df$label, cut(df$NoOfLettersInURL, breaks = breaks, 
                              labels = labels))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfLettersInURL")

# OUTLIERS
summary(df_0$NoOfLettersInURL)
summary(df_1$NoOfLettersInURL)

boxplot(df_0$NoOfLettersInURL, df_1$NoOfLettersInURL,
        main = 'Boxplot NoOfLettersInURL', col = c('orange', 'lightblue'),
        ylim = c(min(df_0$NoOfLettersInURL), quantile(df_0$NoOfLettersInURL, 0.97)),
        names = c('phishing', 'legitimate'))

# IQR FOR 'NoOfLettersInURL'
q1 <- quantile(df$NoOfLettersInURL, 0.25)
q3 <- quantile(df$NoOfLettersInURL, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$NoOfLettersInURL < lower_bound | df$NoOfLettersInURL > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$NoOfLettersInURL, 0.25)
q3_0 <- quantile(df_0$NoOfLettersInURL, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$NoOfLettersInURL < lower_bound_0 | df_0$NoOfLettersInURL > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$NoOfLettersInURL, 0.25)
q3_1 <- quantile(df_1$NoOfLettersInURL, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$NoOfLettersInURL < lower_bound_1 | df_1$NoOfLettersInURL > upper_bound_1)

outliers_0  
outliers_1

# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$NoOfLettersInURL, 0.75) - quantile(df_0$NoOfLettersInURL, 0.25)
M1_0 <- quantile(df_0$NoOfLettersInURL, 0.5) - 1.57*IQR_0/sqrt(length(df_0$NoOfLettersInURL))
M2_0 <- quantile(df_0$NoOfLettersInURL, 0.5) + 1.57*IQR_0/sqrt(length(df_0$NoOfLettersInURL))

IQR_1 <- quantile(df_1$NoOfLettersInURL, 0.75) - quantile(df_1$NoOfLettersInURL, 0.25)
M1_1 <- quantile(df_1$NoOfLettersInURL, 0.5) - 1.57*IQR_1/sqrt(length(df_1$NoOfLettersInURL))
M2_1 <- quantile(df_1$NoOfLettersInURL, 0.5) + 1.57*IQR_1/sqrt(length(df_1$NoOfLettersInURL))

# no overlap: the median is different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)

# DISPERSION 
var(df$NoOfLettersInURL)
sd(df$NoOfLettersInURL)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$NoOfLettersInURL)
kurtosis_value_0 <- kurtosis(df_0$NoOfLettersInURL)

skw_value_1 <- skewness(df_1$NoOfLettersInURL)
kurtosis_value_1 <- kurtosis(df_1$NoOfLettersInURL)

density_0 <- density(df_0$NoOfLettersInURL, to = 100)
density_1 <- density(df_1$NoOfLettersInURL)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "NoOfLettersInURL", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "NoOfLettersInURL", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$NoOfLettersInURL, df$label)

#-------------------------------------------------------------------------------
# Attribute LetterRatioInURL

summary(df$LetterRatioInURL)

# CORRELATION WITH SIMILAR FEATURE
cor(df$LetterRatioInURL, df$NoOfLettersInURL)

# DISPERSION 
var(df$LetterRatioInURL)
sd(df$LetterRatioInURL)

# CORRELATION WITH TARGET
cor(df$LetterRatioInURL, df$label)

# delete this feature because has less variance than NoLettersInURL
df <- subset(df, select = -LetterRatioInURL)

#-------------------------------------------------------------------------------
# ATTRIBUTRE NoOfDegitsInURL

summary(df$NoOfDegitsInURL)

breaks <- c(-1, 0, 5, 10, 15, 20, 300) 

labels <- c("0", "(0-5]", "(5-10]", "(10-15]", "(15-20]", "(20-300]")

j_freq <- table(df$label, cut(df$NoOfDegitsInURL, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfDigitsInURL")

# OUTLIERS
summary(df_0$NoOfDegitsInURL)
summary(df_1$NoOfDegitsInURL)

boxplot(df_0$NoOfDegitsInURL, df_1$NoOfDegitsInURL,
        main = 'Boxplot NoOfDigitsInURL', col = c('orange', 'lightblue'),
        ylim = c(min(df_0$NoOfDegitsInURL), quantile(df_0$NoOfDegitsInURL, 0.97)),
        names = c('phishing', 'legitimate'))

# IQR FOR 'NoOfDigitsInURL'
q1 <- quantile(df$NoOfDegitsInURL, 0.25)
q3 <- quantile(df$NoOfDegitsInURL, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$NoOfDegitsInURL < lower_bound | df$NoOfDegitsInURL > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$NoOfDegitsInURL, 0.25)
q3_0 <- quantile(df_0$NoOfDegitsInURL, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$NoOfDegitsInURL < lower_bound_0 | df_0$NoOfDegitsInURL > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$NoOfDegitsInURL, 0.25)
q3_1 <- quantile(df_1$NoOfDegitsInURL, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$NoOfDegitsInURL < lower_bound_1 | df_1$NoOfDegitsInURL > upper_bound_1)

outliers_0  
outliers_1

# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$NoOfDegitsInURL, 0.75) - quantile(df_0$NoOfDegitsInURL, 0.25)
M1_0 <- quantile(df_0$NoOfDegitsInURL, 0.5) - 1.57*IQR_0/sqrt(length(df_0$NoOfDegitsInURL))
M2_0 <- quantile(df_0$NoOfDegitsInURL, 0.5) + 1.57*IQR_0/sqrt(length(df_0$NoOfDegitsInURL))

IQR_1 <- quantile(df_1$NoOfDegitsInURL, 0.75) - quantile(df_1$NoOfDegitsInURL, 0.25)
M1_1 <- quantile(df_1$NoOfDegitsInURL, 0.5) - 1.57*IQR_1/sqrt(length(df_1$NoOfDegitsInURL))
M2_1 <- quantile(df_1$NoOfDegitsInURL, 0.5) + 1.57*IQR_1/sqrt(length(df_1$NoOfDegitsInURL))

# overlap: the median isn't different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)

# DISPERSION 
var(df$NoOfDegitsInURL)
sd(df$NoOfDegitsInURL)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$NoOfDegitsInURL)
kurtosis_value_0 <- kurtosis(df_0$NoOfDegitsInURL)

skw_value_1 <- skewness(df_1$NoOfDegitsInURL)
kurtosis_value_1 <- kurtosis(df_1$NoOfDegitsInURL)

density_0 <- density(df_0$NoOfDegitsInURL, to=50)
density_1 <- density(df_1$NoOfDegitsInURL)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "LetterRatioInURL", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "LetterRatioInURL", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$NoOfDegitsInURL, df$label)

#-------------------------------------------------------------------------------
# ATTRIBUTE DegitRatioInURL

summary(df$DegitRatioInURL)

# DISPERSION
var(df$DegitRatioInURL)
sd(df$DegitRatioInURL)

# CORRELATION WITH SIMILAR FEATURE
cor(df$DegitRatioInURL, df$NoOfDegitsInURL)

# CORRELATION WITH TARGET
cor(df$DegitRatioInURL, df$label)

# delete this feature because has less variance than NoOfDigitsInURL
df <- subset(df, select = -DegitRatioInURL)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfEqualsInURL

summary(df$NoOfEqualsInURL)

# DISPERSION
var(df$NoOfEqualsInURL)
sd(df$NoOfEqualsInURL)

# CORRELATION
cor(df$NoOfEqualsInURL, df$label)

# TODO: study correlations with label 
