// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/chainstaterebuildassistanttests.h>

#include <qt/chainstaterebuildassistant.h>

#include <QTest>

using namespace ChainstateRebuildAssistant;

void ChainstateRebuildAssistantTests::decisionMatrix()
{
    QCOMPARE(ResolveAction(Condition::REBUILD_REQUIRED, Choice::AUTOMATIC),
             Action::RELAUNCH_CHAINSTATE_REBUILD);
    QCOMPARE(ResolveAction(Condition::REBUILD_REQUIRED, Choice::MANUAL),
             Action::SHOW_CHAINSTATE_INSTRUCTIONS);
    QCOMPARE(ResolveAction(Condition::REBUILD_REQUIRED, Choice::CLOSED),
             Action::SHOW_CHAINSTATE_INSTRUCTIONS);
    QCOMPARE(ResolveAction(Condition::FULL_REINDEX_REQUIRED, Choice::AUTOMATIC),
             Action::SHOW_FULL_REINDEX_INSTRUCTIONS);
    QCOMPARE(ResolveAction(Condition::ALREADY_COMPLETE, Choice::AUTOMATIC),
             Action::CONTINUE_STARTUP);
}

void ChainstateRebuildAssistantTests::phaseParsing()
{
    QCOMPARE(ParsePhase(QStringLiteral("rebuild")), Phase::REBUILD);
    QCOMPARE(ParsePhase(QStringLiteral("verify")), Phase::VERIFY);
    QCOMPARE(ParsePhase(QStringLiteral("REBUILD")), Phase::NONE);
    QCOMPARE(ParsePhase(QStringLiteral("unexpected")), Phase::NONE);
    QCOMPARE(PhaseName(Phase::REBUILD), QStringLiteral("rebuild"));
    QCOMPARE(PhaseName(Phase::VERIFY), QStringLiteral("verify"));
    QVERIFY(PhaseName(Phase::NONE).isEmpty());
}

void ChainstateRebuildAssistantTests::automaticArgumentsAreOneShot()
{
    const QStringList original{
        QStringLiteral("-datadir=/Volumes/Node Data/Nick's node"),
        QStringLiteral("-testnet=1"),
        QStringLiteral("-onlynet=onion"),
        QStringLiteral("-wallet=Quantum \"One\""),
        QStringLiteral("--reindex=1"),
        QStringLiteral("/reindex-chainstate=1"),
        QStringLiteral("-noreindex=0"),
        QStringLiteral("-noreindex-chainstate=0"),
        QStringLiteral("-gui-chainstate-rebuild=verify"),
    };

    QCOMPARE(BuildRelaunchArguments(original, Phase::REBUILD), QStringList({
        original[0], original[1], original[2], original[3],
        QStringLiteral("-reindex-chainstate"),
        QStringLiteral("-gui-chainstate-rebuild=rebuild"),
    }));
    QCOMPARE(BuildRelaunchArguments(original, Phase::VERIFY), QStringList({
        original[0], original[1], original[2], original[3],
        QStringLiteral("-gui-chainstate-rebuild=verify"),
    }));
}

void ChainstateRebuildAssistantTests::manualArgumentsAreOneShot()
{
    const QStringList original{
        QStringLiteral("--datadir=/tmp/Blackcoin Data"),
        QStringLiteral("--regtest"),
        QStringLiteral("--reindex-chainstate=false"),
        QStringLiteral("--noreindex=1"),
        QStringLiteral("-gui-chainstate-rebuild=rebuild"),
    };
    QCOMPARE(BuildManualRebuildArguments(original), QStringList({
        original[0], original[1], QStringLiteral("-reindex-chainstate"),
    }));
}

void ChainstateRebuildAssistantTests::fullReindexArgumentsAreOneShot()
{
    const QStringList original{
        QStringLiteral("-datadir=C:/Blackcoin Node"),
        QStringLiteral("-signet"),
        QStringLiteral("-prune=550"),
        QStringLiteral("--noprune=0"),
        QStringLiteral("--reindex-chainstate"),
        QStringLiteral("-reindex=0"),
    };
    QCOMPARE(BuildFullReindexArguments(original), QStringList({
        original[0], original[1], QStringLiteral("-prune=0"),
        QStringLiteral("-reindex"),
    }));
}

void ChainstateRebuildAssistantTests::commandFormatting()
{
    QCOMPARE(
        FormatCommand(
            QStringLiteral("/Applications/Blackcoin Core/blackcoin-qt"),
            {QStringLiteral("-datadir=/Users/Nick's Data"),
             QStringLiteral("-wallet=Quantum \"One\"")},
            CommandPlatform::UNIX),
        QStringLiteral("'/Applications/Blackcoin Core/blackcoin-qt' "
                       "'-datadir=/Users/Nick'\\''s Data' "
                       "'-wallet=Quantum \"One\"'"));

    QCOMPARE(
        FormatCommand(
            QStringLiteral("C:\\Program Files\\Blackcoin\\blackcoin-qt.exe"),
            {QStringLiteral("-datadir=C:\\Users\\Nick Rogers\\Blackcoin"),
             QStringLiteral("-testnet=1")},
            CommandPlatform::WINDOWS),
        QStringLiteral("\"C:\\Program Files\\Blackcoin\\blackcoin-qt.exe\" "
                       "\"-datadir=C:\\Users\\Nick Rogers\\Blackcoin\" "
                       "-testnet=1"));
}
