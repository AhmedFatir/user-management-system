import React from 'react'
import styles from './404.module.css'

const NotFound = () => {
  return (
    <div className={styles.container}>
      <div className={styles.left}>
        <svg
          width="300"
          height="300"
          viewBox="0 0 300 300"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path
            d="M153.01 33.2a6 6 0 0 1 2.18 2.18l129.7 223.61a6 6 0 0 1-5.19 9.01H20.3a6 6 0 0 1-5.2-9.01L144.8 35.38a6 6 0 0 1 8.21-2.18ZM150.02 204a14.01 14.01 0 1 0-.02 28.02 14.01 14.01 0 0 0 .02-28.02Zm4.8-89h-9.65a6 6 0 0 0-6 6.17l1.5 52a6 6 0 0 0 6 5.83h6.67a6 6 0 0 0 6-5.83l1.48-52a6 6 0 0 0-6-6.17Z"
            fill="#000"
            fillRule="evenodd"
          />
        </svg>
      </div>
      <div className={styles.right}>
        <div className={styles.textContainer}>
          <h1 className={styles.code}>404</h1>
          <div className={styles.status}>Page Not Found</div>
          <div className={styles.description}>
            Oops! The page you are looking for doesn’t exist or has been moved.
          </div>
          <div className={styles.buttonContainer}>
            <a href="/" className={styles.button}>Back to home</a>
          </div>
          <div className={styles.footer}>
            Please check the URL or go back to the homepage.
          </div>
        </div>
      </div>
    </div>
  );
}

export default NotFound