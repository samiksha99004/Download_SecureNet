/**
 * SecureNet — Card
 *
 * Base surface container used throughout the app.
 */

import type { ReactNode, HTMLAttributes } from 'react';
import { cn } from '../../utils/cn';
import styles from './Card.module.css';

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  padding?: 'sm' | 'md' | 'lg' | 'none';
  className?: string;
}

export function Card({ children, padding = 'md', className, ...rest }: CardProps) {
  return (
    <div
      className={cn(styles.card, styles[`padding-${padding}`], className)}
      {...rest}
    >
      {children}
    </div>
  );
}
