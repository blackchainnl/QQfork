// Copyright (c) 2026 The Blackcoin - Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TEST_THEMETESTS_H
#define BITCOIN_QT_TEST_THEMETESTS_H

#include <QObject>

class ThemeTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void walletPagesFollowLightAndDarkPalettes();
    void transactionColorsMeetContrastTarget();
};

#endif // BITCOIN_QT_TEST_THEMETESTS_H
