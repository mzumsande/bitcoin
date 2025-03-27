#include <iostream>
#include <chrono>
#include <logging.h>

#ifndef BITCOIN_VALIDATIONTIMER_H
#define BITCOIN_VALIDATIONTIMER_H

class ValidationTimer {
public:
    ValidationTimer() {
        LogPrintf("MZ validation timer started");
        startOutside();
    }

    void startInside() {
        stopOutside();
        insideStart = std::chrono::steady_clock::now();
    }

    void stopInside() {
        insideDuration += std::chrono::steady_clock::now() - insideStart;
        startOutside();
    }

    void startOutside() {
        outsideStart = std::chrono::steady_clock::now();
    }

    void stopOutside() {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - outsideStart).count();
        if (duration > 30) {
            LogPrintf("MZMZ Warning: More than 30 seconds spent outside ABC!");
        }
        outsideDuration += now - outsideStart;
    }

    void printResults() {
        auto totalSeconds = std::chrono::duration_cast<std::chrono::seconds>(insideDuration + outsideDuration).count();
        auto insideSeconds = std::chrono::duration_cast<std::chrono::seconds>(insideDuration).count();
        auto outsideSeconds = std::chrono::duration_cast<std::chrono::seconds>(outsideDuration).count();

        LogPrintf("MZ Time spent inside ABC: %i min %i sec", insideSeconds / 60,  insideSeconds % 60 );
        LogPrintf("MZ Time spent outside ABC: %i min %i sec", outsideSeconds / 60,  outsideSeconds % 60 );

        double insidePercentage = (totalSeconds > 0) ? (insideSeconds * 100.0 / totalSeconds) : 0;
        LogPrintf("MZ Percentage of time spent inside ABC: %i", insidePercentage);
        LogPrintf("MZ total time: %i", totalSeconds);
    }

private:
    std::chrono::steady_clock::time_point insideStart, outsideStart;
    std::chrono::duration<double> insideDuration{0}, outsideDuration{0};
};

#endif // BITCOIN_VALIDATIONTIMER_H
