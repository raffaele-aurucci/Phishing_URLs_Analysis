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

# disable scientific notation view
options(scipen = 999)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'label'

# 0 -> phishing URL
# 1 -> legitimate URL

table(df$label)

# # Count values > 100k in LargestLineLength
# count_above_100k <- sum(df$LargestLineLength > 100000, na.rm = TRUE)
# count_above_100k
# 
# # Remove values > 100k in LargestLineLength
# df <- df[df$LargestLineLength <= 100000 | is.na(df$LargestLineLength), ]

# undersampling to balance dataset
indices_label_1 <- which(df$label == 1)
indices_to_remove <- sample(indices_label_1, 3671) # 3424
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

labels <- c("[0,0.1]", "(0.1,0.2]", "(0.2,0.3]", "(0.3,0.4]", "(0.4,0.5]",
            "(0.5,0.6]", "(0.6,0.7]", "(0.7,0.8]", "(0.8,0.9]", "(0.9,1.0]")
 
j_freq <- table(df$label, cut(df$TLDEncoding, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta TLDEncoding")

# OUTLIERS
summary(df_0$TLDEncoding)
summary(df_1$TLDEncoding)

boxplot(df_0$TLDEncoding, df_1$TLDEncoding,
        main = 'Boxplot TLDEncoding', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))

# IQR FOR 'TLDEncoding'
q1 <- quantile(df$TLDEncoding, 0.25)
q3 <- quantile(df$TLDEncoding, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$TLDEncoding < lower_bound | df$TLDEncoding > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$TLDEncoding, 0.25)
q3_0 <- quantile(df_0$TLDEncoding, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$TLDEncoding < lower_bound_0 | df_0$TLDEncoding > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$TLDEncoding, 0.25)
q3_1 <- quantile(df_1$TLDEncoding, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$TLDEncoding < lower_bound_1 | df_1$TLDEncoding > upper_bound_1)

outliers_0  
outliers_1 


# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$TLDEncoding, 0.75) - quantile(df_0$TLDEncoding, 0.25)
M1_0 <- quantile(df_0$TLDEncoding, 0.5) - 1.57*IQR_0/sqrt(length(df_0$TLDEncoding))
M2_0 <- quantile(df_0$TLDEncoding, 0.5) + 1.57*IQR_0/sqrt(length(df_0$TLDEncoding))

IQR_1 <- quantile(df_1$TLDEncoding, 0.75) - quantile(df_1$TLDEncoding, 0.25)
M1_1 <- quantile(df_1$TLDEncoding, 0.5) - 1.57*IQR_1/sqrt(length(df_1$TLDEncoding))
M2_1 <- quantile(df_1$TLDEncoding, 0.5) + 1.57*IQR_1/sqrt(length(df_1$TLDEncoding))

# overlap: the median isn't different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)

# DISTRIBUTION FORM
skw_value <- skewness(df$TLDEncoding)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$TLDEncoding)  # leptokurtic
skw_value
kurtosis_value

density <- density(df$TLDEncoding)

plot(density, main = "Distribuzione TLDEncoding", 
     col = "orange", lwd = 2, xlab = 'TLDEncoding')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

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
cor(df$TLDEncoding, df$label, method = 'spearman')

# ------------------------------------------------------------------------------
# ATTRIBUTE 'URLLenght'

summary(df$URLLength)

breaks <- c(0, 10, 20, 30, 40, 50, 1000) 

labels <- c("[0,10]", "(10,20]", "(20,30]", "(30,40]", "(40,50]", "(50,1000]")

j_freq <- table(df$label, cut(df$URLLength, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

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
cor(df$URLLength, df$label, method = 'spearman')

# ------------------------------------------------------------------------------
# ATTRIBUTE 'DomainLenght'

summary(df$DomainLength)

breaks <- c(0, 10, 20, 30, 40, 50, 100) 

labels <- c("[0,10]", "(10,20]", "(20,30]", "(30,40]", "(40,50]", "(50,100]")

j_freq <- table(df$label, cut(df$DomainLength, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

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
cor(df$DomainLength, df$label, method = 'spearman')
# ------------------------------------------------------------------------------
# ATTRIBUTE 'IsDomainIP'

table(df$IsDomainIP)

cor(df$IsDomainIP, df$label)
cor(df$IsDomainIP, df$label, method = 'spearman')

# delete attribute because have only 81 value setting to 1
df <- subset(df, select = -IsDomainIP)
# ------------------------------------------------------------------------------
# ATTRIBUTE 'URLSimilarityIndex'

summary(df$URLSimilarityIndex)

breaks <- c(-1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100) 

labels <- c("[0,10]", "(10,20]", "(20,30]", "(30,40]", "(40,50]", "(50,60]",
            "(60,70]", "(70,80]", "(80,90]", "(90,100]")

j_freq <- table(df$label, cut(df$URLSimilarityIndex, breaks = breaks, labels = labels))
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
cor(df$URLSimilarityIndex, df$label, method = 'spearman')

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

labels <- c("[0,10]", "(10,20]", "(20,30]", "(30,40]", "(40,50]", "(50,60]", 
            "(60,70]", "(70,80]", "(80,90]", "(90,100]")

j_freq <- table(df$label, cut(df$URLTitleMatchScore, breaks = breaks, 
                              labels = labels))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta URLTitleMatchScore")

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

# DISTRIBUTION FORM
skw_value <- skewness(df$URLTitleMatchScore)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$URLTitleMatchScore)  # leptokurtic
skw_value
kurtosis_value

density <- density(df$URLTitleMatchScore)

plot(density, main = "Distribuzione URLTitleMatchScore", 
     col = "orange", lwd = 2, xlab = 'URLTitleMatchScore')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

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
cor(df$URLTitleMatchScore, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE 'DomainTitleMatchScore'

summary(df$DomainTitleMatchScore)

breaks <- c(-1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100) 

labels <- c("[0,10]", "(10-20]", "(20-30]", "(30-40]", "(40-50]", "(50-60]", 
            "(60-70]", "(70-80]", "(80-90]", "(90-100]")

j_freq <- table(df$label, cut(df$DomainTitleMatchScore, breaks = breaks, 
                              labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta DomainTitleMatchScore")

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

# DISTRIBUTION FORM
skw_value <- skewness(df$DomainTitleMatchScore)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$DomainTitleMatchScore)  # leptokurtic
skw_value
kurtosis_value

density <- density(df$DomainTitleMatchScore)

plot(density, main = "Distribuzione DomainTitleMatchScore", 
     col = "orange", lwd = 2, xlab = 'DomainTitleMatchScore')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

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
cor(df$DomainTitleMatchScore, df$label, method = 'spearman')

# TODO: study correlation with URLTitleMatchScore
#-------------------------------------------------------------------------------
# ATTRIBUTE 'TLDLenght'

summary(df$TLDLength)

j_freq <- table(df$label, 
                cut(df$TLDLength,
                    breaks = c(1, 2, 3, 4, 13), 
                    labels = c("2", "3", "4", "[5-13]"), 
                    right = TRUE))

j_freq_rel <- prop.table(j_freq)
j_freq_rel

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
cor(df$TLDLength, df$label, method = 'spearman')

# delete this feature becasue has lower variance, overlap median and corr = 0

df <- subset(df, select = -TLDLength)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfSubDomain

summary(df$NoOfSubDomain)

j_freq <- table(df$label, df$NoOfSubDomain)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

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
cor(df$NoOfSubDomain, df$label, method = 'spearman')

df <- subset(df, select = -NoOfSubDomain)
#-------------------------------------------------------------------------------
# ATTRIBUTE HasObfuscation

table(df$HasObfuscation)

# CORRELATION WITH TARGET
cor(df$HasObfuscation, df$label)
cor(df$HasObfuscation, df$label, method = 'spearman')

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
cor(df$NoOfObfuscatedChar, df$label, method = 'spearman')

df <- subset(df, select = -NoOfObfuscatedChar)
#-------------------------------------------------------------------------------
# ATTRIBUTE ObfuscationRatio

summary(df$ObfuscationRatio)

j_freq <- table(ObfuscationRatio = ifelse(df$ObfuscationRatio == 0, "0", ">0"),
                label = df$label)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION 
var(df$ObfuscationRatio)
sd(df$ObfuscationRatio)

# CORRELATION WITH TARGET
cor(df$ObfuscationRatio, df$label)
cor(df$ObfuscationRatio, df$label, method = 'spearman')

df <- subset(df, select = -ObfuscationRatio)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfLettersInURL

summary(df$NoOfLettersInURL)

breaks <- c(-1, 10, 20, 30, 40, 50, 60, 70, 80, 100, 150, 700) 

labels <- c("[0,10]", "(10,20]", "(20,30]", "(30,40]", "(40,50]", "(50,60]", 
            "(60,70]", "(70,80]", "(80,100]", "(100,150]", "(150,700]")

j_freq <- table(df$label, cut(df$NoOfLettersInURL, breaks = breaks, 
                              labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

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

# DISTRIBUTION FORM
skw_value <- skewness(df$NoOfLettersInURL)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$NoOfLettersInURL)  # leptokurtic
skw_value
kurtosis_value

density <- density(df$NoOfLettersInURL)

plot(density, main = "Distribuzione NoOfLettersInURL", 
     col = "orange", lwd = 2, xlab = 'NoOfLettersInURL')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

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
cor(df$NoOfLettersInURL, df$label, method = 'spearman')

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
cor(df$LetterRatioInURL, df$label, method = 'spearman')

# delete this feature because has less variance than NoLettersInURL
df <- subset(df, select = -LetterRatioInURL)

#-------------------------------------------------------------------------------
# ATTRIBUTRE NoOfDegitsInURL

summary(df$NoOfDegitsInURL)

breaks <- c(-1, 0, 5, 10, 15, 20, 300) 

labels <- c("0", "(0,5]", "(5,10]", "(10,15]", "(15,20]", "(20,300]")

j_freq <- table(df$label, cut(df$NoOfDegitsInURL, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

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

# DISTRIBUTION FORM
skw_value <- skewness(df$NoOfDegitsInURL)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$NoOfDegitsInURL)  # leptokurtic
skw_value
kurtosis_value

density <- density(df$NoOfDegitsInURL, to=50)

plot(density, main = "Distribuzione NoOfDigitsInURL", 
     col = "orange", lwd = 2, xlab = 'NoOfDegitsInURL')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

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
     col = "orange", lwd = 2, xlab = "NoOfDigitsInURL", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "NoOfDigitsInURL", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$NoOfDegitsInURL, df$label)
cor(df$NoOfDegitsInURL, df$label, method = 'spearman')

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
cor(df$DegitRatioInURL, df$label, method = 'spearman')

# delete this feature because has less variance than NoOfDigitsInURL
df <- subset(df, select = -DegitRatioInURL)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfEqualsInURL

summary(df$NoOfEqualsInURL)

breaks <- c(-1, 0, 5, 10, 15) 

labels <- c("0", "(0,5]", "(5,10]", "(10,15]")

j_freq <- table(df$label, cut(df$NoOfEqualsInURL, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfEqualsInURL")

# DISPERSION
var(df$NoOfEqualsInURL)
sd(df$NoOfEqualsInURL)

# CORRELATION
cor(df$NoOfEqualsInURL, df$label)
cor(df$NoOfEqualsInURL, df$label, method = 'spearman')

# df <- subset(df, select = -NoOfEqualsInURL)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfQMarkInURL

summary(df$NoOfQMarkInURL)

j_freq <- table(df$label, df$NoOfQMarkInURL)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfEqualsInURL")

# DISPERSION
var(df$NoOfQMarkInURL)
sd(df$NoOfQMarkInURL)

# CORRELATION
cor(df$NoOfQMarkInURL, df$label)
cor(df$NoOfQMarkInURL, df$label, method = 'spearman')

# df <- subset(df, select = -NoOfQMarkInURL)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfAmpersandInURL

summary(df$NoOfAmpersandInURL)

j_freq <- table(NoOfAmpersandInURL = ifelse(df$NoOfAmpersandInURL == 0, "0", ">0"),
      label = df$label)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfAmpersandInURL)
sd(df$NoOfAmpersandInURL)

# CORRELATION
cor(df$NoOfAmpersandInURL, df$label)
cor(df$NoOfAmpersandInURL, df$label, method = 'spearman')

# df <- subset(df, select = -NoOfAmpersandInURL)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfOtherSpecialCharsInURL

summary(df$NoOfOtherSpecialCharsInURL)

breaks <- c(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 115) 

labels <- c("(0,1]", "(1,2]", "(2,3]", "(3,4]", "(4,5]", "(5,6]", 
            "(6,7]", "(7,8]", "(8,9]", "(9,10]", "(10,112]")

j_freq <- table(df$label, cut(df$NoOfOtherSpecialCharsInURL, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfOtherSpecialCharsInURL")

# DISPERSION
var(df$NoOfOtherSpecialCharsInURL)
sd(df$NoOfOtherSpecialCharsInURL)

# CORRELATION
cor(df$NoOfOtherSpecialCharsInURL, df$label)
cor(df$NoOfOtherSpecialCharsInURL, df$label, method = 'spearman')

# Create a new feature 'NoOfSpecialCharsInURL' that aggregate the value of:
# - NoOfOtherSpecialCharsInURL
# - NoOfAmpersandInURL
# - NoOfQMarkInURL
# - NoOfEqualsInURL

df['NoOfSpecialCharsInURL'] <- df['NoOfOtherSpecialCharsInURL'] + 
                               df['NoOfAmpersandInURL'] + df['NoOfQMarkInURL'] + 
                               df['NoOfEqualsInURL']

summary(df$NoOfSpecialCharsInURL)

breaks <- c(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 122) 

labels <- c("(0,1]", "(1,2]", "(2,3]", "(3,4]", "(4,5]", "(5,6]", 
            "(6,7]", "(7,8]", "(8,9]", "(9,10]", "(10,121]")

j_freq <- table(df$label, cut(df$NoOfSpecialCharsInURL, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfSpecialCharsInURL")

# reorder column
cols_order <- append(names(df), 'NoOfSpecialCharsInURL', after = 5)
df <- df[, cols_order]

# delete other feature
df <- subset(df, select = -NoOfOtherSpecialCharsInURL)
df <- subset(df, select = -NoOfAmpersandInURL)
df <- subset(df, select = -NoOfQMarkInURL)
df <- subset(df, select = -NoOfEqualsInURL)
df <- subset(df, select = -NoOfSpecialCharsInURL.1)

# update df_0 and df_1
df_0 <- df[df$label == 0, ]
df_1 <- df[df$label == 1, ]

# DISPERSION
var(df$NoOfSpecialCharsInURL)
sd(df$NoOfSpecialCharsInURL)

# OUTLIERS
summary(df_0$NoOfSpecialCharsInURL)
summary(df_1$NoOfSpecialCharsInURL)

boxplot(df_0$NoOfSpecialCharsInURL, df_1$NoOfSpecialCharsInURL,
        main = 'Boxplot NoOfSpecialCharsInURL', col = c('orange', 'lightblue'),
        ylim = c(min(df_0$NoOfSpecialCharsInURL), quantile(df_0$NoOfSpecialCharsInURL, 0.99)),
        names = c('phishing', 'legitimate'))

# IQR FOR 'NoOfSpecialCharsInURL'
q1 <- quantile(df$NoOfSpecialCharsInURL, 0.25)
q3 <- quantile(df$NoOfSpecialCharsInURL, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$NoOfSpecialCharsInURL < lower_bound | df$NoOfSpecialCharsInURL > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$NoOfSpecialCharsInURL, 0.25)
q3_0 <- quantile(df_0$NoOfSpecialCharsInURL, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$NoOfSpecialCharsInURL < lower_bound_0 | df_0$NoOfSpecialCharsInURL > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$NoOfSpecialCharsInURL, 0.25)
q3_1 <- quantile(df_1$NoOfSpecialCharsInURL, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$NoOfSpecialCharsInURL < lower_bound_1 | df_1$NoOfSpecialCharsInURL > upper_bound_1)

outliers_0  
outliers_1

# OVERLAP MEDIAN
IQR_0 <- quantile(df_0$NoOfSpecialCharsInURL, 0.75) - quantile(df_0$NoOfSpecialCharsInURL, 0.25)
M1_0 <- quantile(df_0$NoOfSpecialCharsInURL, 0.5) - 1.57*IQR_0/sqrt(length(df_0$NoOfSpecialCharsInURL))
M2_0 <- quantile(df_0$NoOfSpecialCharsInURL, 0.5) + 1.57*IQR_0/sqrt(length(df_0$NoOfSpecialCharsInURL))

IQR_1 <- quantile(df_1$NoOfSpecialCharsInURL, 0.75) - quantile(df_1$NoOfSpecialCharsInURL, 0.25)
M1_1 <- quantile(df_1$NoOfSpecialCharsInURL, 0.5) - 1.57*IQR_1/sqrt(length(df_1$NoOfSpecialCharsInURL))
M2_1 <- quantile(df_1$NoOfSpecialCharsInURL, 0.5) + 1.57*IQR_1/sqrt(length(df_1$NoOfSpecialCharsInURL))

# no overlap: the median is different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)

# DISTRIBUTION FORM
skw_value <- skewness(df$NoOfSpecialCharsInURL)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$NoOfSpecialCharsInURL)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$NoOfSpecialCharsInURL)
h_sturges <- (max(df$NoOfSpecialCharsInURL) - min(df$NoOfSpecialCharsInURL)) / sqrt(n)
density_sturges <- density(df$NoOfSpecialCharsInURL, bw = h_sturges)

plot(density_sturges, main = "Distribuzione NoOfSpecialCharsInURL", 
     col = "orange", lwd = 2, xlab = 'NoOfSpecialCharsInURL')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$NoOfSpecialCharsInURL)
kurtosis_value_0 <- kurtosis(df_0$NoOfSpecialCharsInURL)

skw_value_1 <- skewness(df_1$NoOfSpecialCharsInURL)
kurtosis_value_1 <- kurtosis(df_1$NoOfSpecialCharsInURL)

n <- length(df_0$NoOfSpecialCharsInURL)
h_sturges <- (max(df_0$NoOfSpecialCharsInURL) - min(df_0$NoOfSpecialCharsInURL)) / sqrt(n)
density_0 <- density(df_0$NoOfSpecialCharsInURL, bw = h_sturges)

n <- length(df_1$NoOfSpecialCharsInURL)
h_sturges <- (max(df_1$NoOfSpecialCharsInURL) - min(df_1$NoOfSpecialCharsInURL)) / sqrt(n)
density_1 <- density(df_1$NoOfSpecialCharsInURL, bw = h_sturges)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "NoOfSpecialCharsInURL", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "NoOfSpecialCharsInURL", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION
cor(df$NoOfSpecialCharsInURL, df$label)
cor(df$NoOfSpecialCharsInURL, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE SpecialCharRatioInURL

summary(df$SpacialCharRatioInURL)

breaks = c(0, 0.05, 0.1, 0.15, 0.20, 0.25)

labels <- c("[0,0.05]", "(0.05,0.1]", "(0.1,0.15]", "(0.15,0.2]", "(0.2,0.25]")

j_freq <- table(df$label, cut(df$SpacialCharRatioInURL, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta SpacialCharRatioInURL")

# DISPERSION
var(df$SpacialCharRatioInURL)
sd(df$SpacialCharRatioInURL)

# CORRELATION WITH SIMILAR FEATURE
cor(df$SpacialCharRatioInURL, df$NoOfSpecialCharsInURL)

# CORRELATION
cor(df$SpacialCharRatioInURL, df$label)
cor(df$SpacialCharRatioInURL, df$label, method = 'spearman')

df <- subset(df, select = -SpacialCharRatioInURL)
#-------------------------------------------------------------------------------
# ATTRIBUTE IsHTTPS

summary(df$IsHTTPS)

j_freq <- table(df$label, df$IsHTTPS)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$IsHTTPS)
sd(df$IsHTTPS)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta IsHTTPS")

# CORRELATION
cor(df$IsHTTPS, df$label)
cor(df$IsHTTPS, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE LineOfCode

summary(df$LineOfCode)

breaks = c(0, 2, 12, 50, 100, 1000, 210.000)

labels = c("(1,2]", "(2,12]", "(12, 50]", "(50, 100]", "(100, 1000]", 
           "(1000, 210k]")

j_freq <- table(df$label, cut(df$LineOfCode, breaks = breaks, labels = labels))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta LineOfCode")

#DISPERSION
var(df$LineOfCode)
sd(df$LineOfCode)

# OUTLIERS
summary(df_0$LineOfCode)
summary(df_1$LineOfCode)

boxplot(df_0$LineOfCode, df_1$LineOfCode,
        main = 'Boxplot LineOfCode', col = c('orange', 'lightblue'),
        ylim = c(min(df_0$LineOfCode), quantile(df_1$LineOfCode, 0.75)),
        names = c('phishing', 'legitimate'))

# IQR FOR 'LineOfCode'
q1 <- quantile(df$LineOfCode, 0.25)
q3 <- quantile(df$LineOfCode, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$LineOfCode < lower_bound | df$LineOfCode > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$LineOfCode, 0.25)
q3_0 <- quantile(df_0$LineOfCode, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$LineOfCode < lower_bound_0 | df_0$LineOfCode > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$LineOfCode, 0.25)
q3_1 <- quantile(df_1$LineOfCode, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$LineOfCode < lower_bound_1 | df_1$LineOfCode > upper_bound_1)

outliers_0  
outliers_1

# DISTRIBUTION FORM
skw_value <- skewness(df$LineOfCode)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$LineOfCode)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$LineOfCode)
h_sturges <- (max(df$LineOfCode) - min(df$LineOfCode)) / sqrt(n)
density_sturges <- density(df$LineOfCode, bw = h_sturges)

plot(density_sturges, main = "Distribuzione LineOfCode", 
     col = "orange", lwd = 2, xlab = 'LineOfCode')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$LineOfCode)
kurtosis_value_0 <- kurtosis(df_0$LineOfCode)

skw_value_1 <- skewness(df_1$LineOfCode)
kurtosis_value_1 <- kurtosis(df_1$LineOfCode)

n <- length(df_0$LineOfCode)
h_sturges <- (max(df_0$LineOfCode) - min(df_0$LineOfCode)) / sqrt(n)
density_0 <- density(df_0$LineOfCode, bw = h_sturges)

n <- length(df_1$LineOfCode)
h_sturges <- (max(df_1$LineOfCode) - min(df_1$LineOfCode)) / sqrt(n)
density_1 <- density(df_1$LineOfCode, bw = h_sturges, to=30000)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "LineOfCode", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "LineOfCode", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION
cor(df$LineOfCode, df$label)
cor(df$LineOfCode, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE LargestLineLength

summary(df$LargestLineLength)

# Substitute value > 100k arbitrarily with 100k
df$LargestLineLength[df$LargestLineLength > 100000] <- 100000

# update df_0 and df_1
df_0 <- df[df$label == 0, ]
df_1 <- df[df$label == 1, ]

breaks <- c(0, 50, 100, 150, 500, 1000, 5000, 20000, 100000)
labels <- c("(0,50]", "(50,100]", "(100,150]", "(150,500]", 
            "(500,1k]", "(1k,5k]", "(5k,20k]", "(20k,100k]")

j_freq <- table(df$label, cut(df$LargestLineLength, breaks = breaks, labels = labels,
                              include.lowest = TRUE))

j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta LargestLineLength")

# OUTLIERS
summary(df_0$LargestLineLength)
summary(df_1$LargestLineLength)

boxplot(df_0$LargestLineLength, df_1$LargestLineLength,
        main = 'Boxplot LargestLineLength', col = c('orange', 'lightblue'),
        ylim = c(min(df_0$LargestLineLength), quantile(df_1$LargestLineLength, 0.95)),
        names = c('phishing', 'legitimate'))


# IQR FOR 'LargestLineLength'
q1 <- quantile(df$LargestLineLength, 0.25)
q3 <- quantile(df$LargestLineLength, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$LargestLineLength < lower_bound | df$LargestLineLength > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$LargestLineLength, 0.25)
q3_0 <- quantile(df_0$LargestLineLength, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$LargestLineLength < lower_bound_0 | df_0$LargestLineLength > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$LargestLineLength, 0.25)
q3_1 <- quantile(df_1$LargestLineLength, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$LargestLineLength < lower_bound_1 | df_1$LargestLineLength > upper_bound_1)

outliers_0  
outliers_1

# DISPERSION
var(df$LargestLineLength)
sd(df$LargestLineLength)

# DISTRIBUTION FORM
skw_value <- skewness(df$LargestLineLength)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$LargestLineLength)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$LargestLineLength)
h_sturges <- (max(df$LargestLineLength) - min(df$LargestLineLength)) / sqrt(n)
density_sturges <- density(df$LargestLineLength, bw = h_sturges)

plot(density_sturges, main = "Distribuzione LargestLineLength", 
     col = "orange", lwd = 2, xlab = 'LineOfCode')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$LargestLineLength)
kurtosis_value_0 <- kurtosis(df_0$LargestLineLength)

skw_value_1 <- skewness(df_1$LargestLineLength)
kurtosis_value_1 <- kurtosis(df_1$LargestLineLength)

n <- length(df_0$LargestLineLength)
h_sturges <- (max(df_0$LargestLineLength) - min(df_0$LargestLineLength)) / sqrt(n)
density_0 <- density(df_0$LargestLineLength, bw = h_sturges)

n <- length(df_1$LargestLineLength)
h_sturges <- (max(df_1$LargestLineLength) - min(df_1$LargestLineLength)) / sqrt(n)
density_1 <- density(df_1$LargestLineLength, bw = h_sturges)

# 1 row, 2 columns
par(mfrow = c(1, 2))  

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "LargestLineLength", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_0, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_0, 2))), 
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "LargestLineLength", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright", 
       legend = c(paste("Skewness:", round(skw_value_1, 2)), 
                  paste("Kurtosis:", round(kurtosis_value_1, 2))), 
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION WITH TARGET
cor(df$LargestLineLength, df$label)
cor(df$LargestLineLength, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE HasTitle

summary(df$HasTitle)

j_freq <- table(df$label, df$HasTitle)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasTitle)
sd(df$HasTitle)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasTitle")

# CORRELATION
cor(df$HasTitle, df$label)
cor(df$HasTitle, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE Title

# delete attribute because have only unique value
df <- subset(df, select = -Title)
#-------------------------------------------------------------------------------
# ATTRIBUTE HasFavicon

summary(df$HasFavicon)

j_freq <- table(df$label, df$HasFavicon)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasTitle)
sd(df$HasTitle)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasFavicon")

# CORRELATION
cor(df$HasFavicon, df$label)
cor(df$HasFavicon, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE Robots

summary(df$Robots)

j_freq <- table(df$label, df$Robots)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$Robots)
sd(df$Robots)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta Robots")

# CORRELATION
cor(df$Robots, df$label)
cor(df$Robots, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE IsResponsive

summary(df$IsResponsive)

j_freq <- table(df$label, df$IsResponsive)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$IsResponsive)
sd(df$IsResponsive)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta IsResponsive")

# CORRELATION
cor(df$IsResponsive, df$label)
cor(df$IsResponsive, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfURLRedirect

summary(df$NoOfURLRedirect)

j_freq <- table(df$label, df$NoOfURLRedirect)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfURLRedirect)
sd(df$NoOfURLRedirect)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfURLRedirect")

# CORRELATION
cor(df$NoOfURLRedirect, df$label)
cor(df$NoOfURLRedirect, df$label, method = 'spearman')

# delete attribute because has 95% of data is setting to 0
df <- subset(df, select = -NoOfURLRedirect)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfSelfRedirect

summary(df$NoOfSelfRedirect)

j_freq <- table(df$label, df$NoOfSelfRedirect)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfSelfRedirect)
sd(df$NoOfSelfRedirect)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfSelfRedirect")

# CORRELATION
cor(df$NoOfSelfRedirect, df$label)
cor(df$NoOfSelfRedirect, df$label, method = 'spearman')

# delete attribute because has 96% of data is setting to 0
df <- subset(df, select = -NoOfSelfRedirect)
#-------------------------------------------------------------------------------
# ATTRIBUTE HasDescription

summary(df$HasDescription)

j_freq <- table(df$label, df$HasDescription)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasDescription)
sd(df$HasDescription)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasDescription")

# CORRELATION
cor(df$HasDescription, df$label)
cor(df$HasDescription, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfPopup

summary(df$NoOfPopup)

j_freq <- table(df$label, cut(df$NoOfPopup, breaks = c(-Inf, 0, 396), labels = c("0", "(0, 396]")))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfPopup")

# DISPERSION
var(df$NoOfPopup)
sd(df$NoOfPopup)

# CORRELATION
cor(df$NoOfPopup, df$label)
cor(df$NoOfPopup, df$label, method = 'spearman')

# delete attribute because has 96% of data is setting to 0
df <- subset(df, select = -NoOfPopup)
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfiFrame - DELETE???

summary(df$NoOfiFrame)

j_freq <- table(df$label, cut(df$NoOfiFrame, breaks = c(-Inf, 0, 10, 172), 
                              labels = c("0", "(0, 10]", "(10, 172]")))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfiFrame)
sd(df$NoOfiFrame)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfiFrame")

# OUTLIERS
summary(df_0$NoOfiFrame)
summary(df_1$NoOfiFrame)

boxplot(df_0$NoOfiFrame, df_1$NoOfiFrame,
        main = 'Boxplot NoOfiFrame', col = c('orange', 'lightblue'),
        ylim = c(min(df_0$NoOfiFrame), quantile(df_1$NoOfiFrame, 0.99)),
        names = c('phishing', 'legitimate'))

# IQR FOR 'NoOfiFrame'
q1 <- quantile(df$NoOfiFrame, 0.25)
q3 <- quantile(df$NoOfiFrame, 0.75)
iqr <- q3 - q1

lower_bound <- q1 - 1.5 * iqr
upper_bound <- q3 + 1.5 * iqr

outliers <- sum(df$NoOfiFrame < lower_bound | df$NoOfiFrame > upper_bound)
outliers

# IQR FOR 'Phishing'
q1_0 <- quantile(df_0$NoOfiFrame, 0.25)
q3_0 <- quantile(df_0$NoOfiFrame, 0.75)
iqr_0 <- q3_0 - q1_0

lower_bound_0 <- q1_0 - 1.5 * iqr_0
upper_bound_0 <- q3_0 + 1.5 * iqr_0

outliers_0 <- sum(df_0$NoOfiFrame < lower_bound_0 | df_0$NoOfiFrame > upper_bound_0)

# IQR FOR 'Legitimate'
q1_1 <- quantile(df_1$NoOfiFrame, 0.25)
q3_1 <- quantile(df_1$NoOfiFrame, 0.75)
iqr_1 <- q3_1 - q1_1

lower_bound_1 <- q1_1 - 1.5 * iqr_1
upper_bound_1 <- q3_1 + 1.5 * iqr_1

outliers_1 <- sum(df_1$NoOfiFrame < lower_bound_1 | df_1$NoOfiFrame > upper_bound_1)

outliers_0
outliers_1

# DISTRIBUTION FORM
skw_value <- skewness(df$NoOfiFrame)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$NoOfiFrame)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$NoOfiFrame)
h_sturges <- (max(df$NoOfiFrame) - min(df$NoOfiFrame)) / sqrt(n)
density_sturges <- density(df$NoOfiFrame, bw = h_sturges)

plot(density_sturges, main = "Distribuzione NoOfiFrame",
     col = "orange", lwd = 2, xlab = 'NoOfiFrame')
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)),
                              paste("Kurtosis:", round(kurtosis_value, 2))),
       bty = "n", col = "black", cex = 0.8)

# DISTRIBUTION FORM FOR Phishing AND Legitimate
skw_value_0 <- skewness(df_0$NoOfiFrame)
kurtosis_value_0 <- kurtosis(df_0$NoOfiFrame)

skw_value_1 <- skewness(df_1$NoOfiFrame)
kurtosis_value_1 <- kurtosis(df_1$NoOfiFrame)

n <- length(df_0$NoOfiFrame)
h_sturges <- (max(df_0$NoOfiFrame) - min(df_0$NoOfiFrame)) / sqrt(n)
density_0 <- density(df_0$NoOfiFrame, bw = h_sturges)

n <- length(df_1$NoOfiFrame)
h_sturges <- (max(df_1$NoOfiFrame) - min(df_1$NoOfiFrame)) / sqrt(n)
density_1 <- density(df_1$NoOfiFrame, bw = h_sturges, to=50)

# 1 row, 2 columns
par(mfrow = c(1, 2))

# phishing
plot(density_0, main = "phishing",
     col = "orange", lwd = 2, xlab = "NoOfiFrame", ylab = "Density",
     ylim = c(0, max(density_0$y)))
legend("topright",
       legend = c(paste("Skewness:", round(skw_value_0, 2)),
                  paste("Kurtosis:", round(kurtosis_value_0, 2))),
       col = "orange", lwd = 2, bty = "n", cex = 0.8)

# legitimate
plot(density_1, main = "legitimate",
     col = "lightblue", lwd = 2, xlab = "NoOfiFrame", ylab = "Density",
     ylim = c(0, max(density_1$y)))
legend("topright",
       legend = c(paste("Skewness:", round(skw_value_1, 2)),
                  paste("Kurtosis:", round(kurtosis_value_1, 2))),
       col = "lightblue", lwd = 2, bty = "n", cex = 0.8)

# reset plot layout
par(mfrow = c(1, 1))

# CORRELATION
cor(df$NoOfiFrame, df$label)
cor(df$NoOfiFrame, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE HasExternalFormSubmit 

summary(df$HasExternalFormSubmit)

j_freq <- table(df$label, df$HasExternalFormSubmit)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasExternalFormSubmit)
sd(df$HasExternalFormSubmit)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasExternalFormSubmit")

# CORRELATION
cor(df$HasExternalFormSubmit, df$label)
cor(df$HasExternalFormSubmit, df$label, method = 'spearman')

# delete attribute because has 96% of data is setting to 0
df <- subset(df, select = -HasExternalFormSubmit)
#-------------------------------------------------------------------------------
# ATTRIBUTE HasSocialNet

summary(df$HasSocialNet)

j_freq <- table(df$label, df$HasSocialNet)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasSocialNet)
sd(df$HasSocialNet)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasSocialNet")

# CORRELATION
cor(df$HasSocialNet, df$label)
cor(df$HasSocialNet, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE HasSubmitButton - DELETE???

summary(df$HasSubmitButton)

j_freq <- table(df$label, df$HasSubmitButton)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasSubmitButton)
sd(df$HasSubmitButton)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasSubmitButton")

# CORRELATION
cor(df$HasSubmitButton, df$label)
cor(df$HasSubmitButton, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE HasHiddenFields - DELETE???

summary(df$HasHiddenFields)

j_freq <- table(df$label, df$HasHiddenFields)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasHiddenFields)
sd(df$HasHiddenFields)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasHiddenFields")

# CORRELATION
cor(df$HasHiddenFields, df$label)
cor(df$HasHiddenFields, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE HasPasswordField

summary(df$HasPasswordField)

j_freq <- table(df$label, df$HasPasswordField)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasPasswordField)
sd(df$HasPasswordField)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasPasswordField")

# CORRELATION
cor(df$HasPasswordField, df$label)
cor(df$HasPasswordField, df$label, method = 'spearman')

# delete attribute because has 90% of data is setting to 0
df <- subset(df, select = -HasPasswordField)
#-------------------------------------------------------------------------------
# ATTRIBUTE Bank 

summary(df$Bank)

j_freq <- table(df$label, df$Bank)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$Bank)
sd(df$Bank)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta Bank")

# CORRELATION
cor(df$Bank, df$label)
cor(df$Bank, df$label, method = 'spearman')

# delete attribute because has 90% of data is setting to 0
df <- subset(df, select = -Bank)
#-------------------------------------------------------------------------------
# ATTRIBUTE Pay 

summary(df$Pay)

j_freq <- table(df$label, df$Pay)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$Pay)
sd(df$Pay)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta Pay")

# CORRELATION
cor(df$Pay, df$label)
cor(df$Pay, df$label, method = 'spearman')

# delete attribute because has 78% of data is setting to 0
df <- subset(df, select = -Pay)
#-------------------------------------------------------------------------------
# ATTRIBUTE Crypto

summary(df$Crypto)

j_freq <- table(df$label, df$Crypto)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$Crypto)
sd(df$Crypto)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta Crypto")

# CORRELATION
cor(df$Crypto, df$label)
cor(df$Crypto, df$label, method = 'spearman')

# delete attribute because has 97% of data is setting to 0
df <- subset(df, select = -Crypto)
#-------------------------------------------------------------------------------
# ATTRIBUTE HasCopyrightInfo - INCLUDE WITH HAS_SOCIAL_NET???

summary(df$HasCopyrightInfo)

j_freq <- table(df$label, df$HasCopyrightInfo)
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$HasCopyrightInfo)
sd(df$HasCopyrightInfo)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta HasCopyrightInfo")

# CORRELATION
cor(df$HasCopyrightInfo, df$label)
cor(df$HasCopyrightInfo, df$label, method = 'spearman')
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfImage - DELETE???

summary(df$NoOfImage)

j_freq <- table(df$label, cut(df$NoOfImage, breaks = c(-Inf, 0, 10, 8956), 
                              labels = c("0", "(0, 10]", "(10, 8956]")))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfiFrame)
sd(df$NoOfiFrame)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfImage")
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfCSS - DELETE???

summary(df$NoOfCSS)

j_freq <- table(df$label, cut(df$NoOfCSS, breaks = c(-Inf, 0, 10, 35820), 
                              labels = c("0", "(0, 10]", "(10, 35820]")))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfCSS)
sd(df$NoOfCSS)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfCSS")
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfJS - DELETE???

summary(df$NoOfJS)

j_freq <- table(df$label, cut(df$NoOfJS, breaks = c(-Inf, 0, 10, 378), 
                              labels = c("0", "(0, 10]", "(10, 378]")))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfJS)
sd(df$NoOfJS)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfJS")
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfSelfRef - DELETE???

summary(df$NoOfSelfRef)

j_freq <- table(df$label, cut(df$NoOfSelfRef, breaks = c(-Inf, 0, 10, 19046), 
                              labels = c("0", "(0, 10]", "(10, 19046]")))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfSelfRef)
sd(df$NoOfSelfRef)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfSelfRef")
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfEmptyRef - DELETE???

summary(df$NoOfEmptyRef)

j_freq <- table(df$label, cut(df$NoOfEmptyRef, breaks = c(-Inf, 0, 10, 1336), 
                              labels = c("0", "(0, 10]", "(10, 1336]")))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfEmptyRef)
sd(df$NoOfEmptyRef)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfEmptyRef")
#-------------------------------------------------------------------------------
# ATTRIBUTE NoOfExternalRef - DELETE???

summary(df$NoOfExternalRef)

j_freq <- table(df$label, cut(df$NoOfExternalRef, breaks = c(-Inf, 0, 10, 19147), 
                              labels = c("0", "(0, 10]", "(10, 19147]")))
j_freq_rel <- prop.table(j_freq)
j_freq_rel

# DISPERSION
var(df$NoOfExternalRef)
sd(df$NoOfExternalRef)

barplot(j_freq_rel, beside=TRUE, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta NoOfExternalRef")
# TODO: INSERT CORRPLOT with label 
