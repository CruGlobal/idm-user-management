package org.ccci.idm.user.query;

import com.google.common.collect.ImmutableList;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.util.List;

@Immutable
public final class BooleanExpression implements Expression {
    public enum Type {AND, OR}

    @Nonnull
    private final Type type;
    @Nonnull
    private final List<Expression> components;

    BooleanExpression(@Nonnull final Type type, @Nonnull final Expression expression,
                      @Nonnull final Expression... expressions) {
        this.type = type;
        components = ImmutableList.<Expression>builder()
                .add(expression)
                .add(expressions)
                .build();
    }

    private BooleanExpression(@Nonnull final BooleanExpression previous, @Nonnull final Expression... expressions) {
        type = previous.type;
        components = ImmutableList.<Expression>builder()
                .addAll(previous.components)
                .add(expressions)
                .build();
    }

    @Nonnull
    public Type getType() {
        return type;
    }

    @Nonnull
    public List<Expression> getComponents() {
        return components;
    }

    @Override
    public Expression and(@Nonnull final Expression... expressions) {
        if (type != Type.AND) {
            return Expression.super.and(expressions);
        }

        return new BooleanExpression(this, expressions);
    }

    @Override
    public Expression or(@Nonnull final Expression... expressions) {
        if (type != Type.OR) {
            return Expression.super.or(expressions);
        }

        return new BooleanExpression(this, expressions);
    }
}
