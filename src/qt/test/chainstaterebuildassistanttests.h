// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_CHAINSTATEREBUILDASSISTANTTESTS_H
#define BITCOIN_QT_TEST_CHAINSTATEREBUILDASSISTANTTESTS_H

#include <QObject>

class ChainstateRebuildAssistantTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void decisionMatrix();
    void phaseParsing();
    void automaticArgumentsAreOneShot();
    void manualArgumentsAreOneShot();
    void fullReindexArgumentsAreOneShot();
    void commandFormatting();
};

#endif // BITCOIN_QT_TEST_CHAINSTATEREBUILDASSISTANTTESTS_H
