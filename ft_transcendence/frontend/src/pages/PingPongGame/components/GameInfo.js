import React from 'react';
import "./gameInfo.css"
import { useTranslation } from 'react-i18next'

const GameInfo = () => {
    const { t } = useTranslation();

    const rules = {
        1: t("1- Victory Condition: The game is won by the first player to score 11 points."),
        2: t("2- Paddle Movement: Control your paddle using the keys you've chosen:"),
        3: t("   • W to move up, S to move down."),
        4: t("   • Arrow Up to move up, Arrow Down to move down."),
        5: t("3- Reconnect Feature: If you quit or disconnect, you have 15 seconds to reconnect and continue the game"),
        6: t("   — but you can only reconnect once. If you disconnect again, the game is forfeited."),
        7: t("4- Stay Focused: You're in a fierce competition—keep your cool and don't lose!"),
    }

    return (
        <div className="game-info-container">
            <h1 className="game-info-title">{t('ABOUT THE GAME')}</h1>
            <ul className="rules-container">
                {Object.values(rules).map((rule, index) => (
                    <li key={index} className="rule-item">{rule}</li>
                ))}
            </ul>
        </div>
    );
}

export default GameInfo;