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

# ------------------------------------------------------------------------------
# ATTRIBUTE 'FILENAME' 

# delete attribute
df <- subset(df, select = -FILENAME)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'URL'

# delete duplicated observations
df <- df[!duplicated(df$URL), ]

# delete attribute because have only unique value
# df <- subset(df, select = -URL)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'Domain'

# delete attribute because have only unique value
df <- subset(df, select = -Domain)

# ------------------------------------------------------------------------------
# ATTRIBUTE 'TLD'

tld_table <- table(df$TLD)

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

# TODO: study in deep

# ------------------------------------------------------------------------------
# ATTRIBUTE 'URLLenght'

summary(df$URLLength)

breaks <- c(0, 10, 20, 30, 40, 50, 1000) 

j_freq <- table(df$label, cut(df$URLLength, breaks = breaks))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta URLLenght")

# outliers
df_0 <- df[df$label == 0, ]
df_1 <- df[df$label == 1, ]

summary(df_0$URLLength)
summary(df_1$URLLength)

boxplot(df_0$URLLength, df_1$URLLength, 
        ylim = c(min(df_0$URLLength), quantile(df_0$URLLength, 0.95)),
        main = 'Boxplot URLLenght', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))


# overlap median

IQR_0 <- quantile(df_0$URLLength, 0.75) - quantile(df_0$URLLength, 0.25)
# lower bound
M1_0 <- quantile(df_0$URLLength, 0.5) - 1.57*IQR_0/sqrt(length(df_0$URLLength))
# upper bound
M2_0 <- quantile(df_0$URLLength, 0.5) + 1.57*IQR_0/sqrt(length(df_0$URLLength))

IQR_1 <- quantile(df_1$URLLength, 0.75) - quantile(df_1$URLLength, 0.25)
# lower bound
M1_1 <- quantile(df_1$URLLength, 0.5) - 1.57*IQR_1/sqrt(length(df_1$URLLength))
# upper bound
M2_1 <- quantile(df_1$URLLength, 0.5) + 1.57*IQR_1/sqrt(length(df_1$URLLength))

# no overlap: the median is different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)

# dispersion
var(df$URLLength)
sd(df$URLLength)

# distribution form
skw_value <- skewness(df$URLLength)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$URLLength)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$URLLength)
h_sturges <- (max(df$URLLength) - min(df$URLLength)) / sqrt(n)
density_sturges <- density(df$URLLength, bw = h_sturges)

plot(density_sturges, main = "Forma della distribuzione URLLength", 
     col = "orange", lwd = 2)
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

# TODO: distribution form for 0 and 1
# ------------------------------------------------------------------------------
# ATTRIBUTE 'DomainLenght'

summary(df$DomainLength)

breaks <- c(0, 10, 20, 30, 40, 50, 100) 

j_freq <- table(df$label, cut(df$DomainLength, breaks = breaks))
j_freq_rel <- prop.table(j_freq)

barplot(j_freq_rel, col = c("orange", "lightblue"),
        legend = c("phishing", "legitimate"),
        main = "Frequenza relativa congiunta DomainLength")

# outliers
df_0 <- df[df$label == 0, ]
df_1 <- df[df$label == 1, ]

summary(df_0$DomainLength)
summary(df_1$DomainLength)

boxplot(df_0$DomainLength, df_1$DomainLength,
        main = 'Boxplot DomainLength', col = c('orange', 'lightblue'),
        names = c('phishing', 'legitimate'))

# overlap median

IQR_0 <- quantile(df_0$DomainLength, 0.75) - quantile(df_0$DomainLength, 0.25)
# lower bound
M1_0 <- quantile(df_0$DomainLength, 0.5) - 1.57*IQR_0/sqrt(length(df_0$DomainLength))
# upper bound
M2_0 <- quantile(df_0$DomainLength, 0.5) + 1.57*IQR_0/sqrt(length(df_0$DomainLength))

IQR_1 <- quantile(df_1$DomainLength, 0.75) - quantile(df_1$DomainLength, 0.25)
# lower bound
M1_1 <- quantile(df_1$DomainLength, 0.5) - 1.57*IQR_1/sqrt(length(df_1$DomainLength))
# upper bound
M2_1 <- quantile(df_1$DomainLength, 0.5) + 1.57*IQR_1/sqrt(length(df_1$DomainLength))

# no overlap: the median is different with a level signification of 5%
c(M1_0, M2_0)
c(M1_1, M2_1)

# dispersion
var(df$DomainLength)
sd(df$DomainLength)

# distribution form
skw_value <- skewness(df$DomainLength)       # (gamma > 0) right skewed
kurtosis_value <- kurtosis(df$DomainLength)  # leptokurtic
skw_value
kurtosis_value

n <- length(df$DomainLength)
h_sturges <- (max(df$DomainLength) - min(df$DomainLength)) / sqrt(n)
density_sturges <- density(df$DomainLength, bw = h_sturges)

plot(density_sturges, main = "Forma della distribuzione DomainLength", 
     col = "orange", lwd = 2)
legend("topright", legend = c(paste("Skewness:", round(skw_value, 2)), 
                              paste("Kurtosis:", round(kurtosis_value, 2))), 
       bty = "n", col = "black", cex = 0.8)

# TODO: distribution form for 0 and 1
# ------------------------------------------------------------------------------
# ATTRIBUTE 'IsDomainIP'

table(df$IsDomainIP)

# delete attribute because have only 81 value setting to 1
df <- subset(df, select = -IsDomainIP)
# ------------------------------------------------------------------------------
# correlations
